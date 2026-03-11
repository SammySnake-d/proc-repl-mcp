#!/usr/bin/env python3
"""
proc-repl-mcp: a small MCP server that provides stateful, interactive subprocess sessions.

Design goals:
- Keep process state across tool calls (like js_repl), by keeping the subprocess alive.
- Work for "REPL-ish" tools (python, r2/rizin CLI, shells, etc.) via a PTY by default.
- Provide both polling ("read") and convenience ("run") APIs.

Security note:
This is a powerful local-RCE capability. By default nothing is allowed unless
PROC_MCP_ALLOW is set.
"""

from __future__ import annotations

import errno
import atexit
import fcntl
import json
import os
import pty
import re
import select
import signal
import shutil
import subprocess
import sys
import termios
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Best-effort ANSI/VT100 escape stripping.
# Covers CSI (ESC [ ...), common single-char escapes (ESC <letter>), and a few
# legacy keypad mode toggles (ESC =, ESC >) that some REPLs emit.
ANSI_RE = re.compile(r"(?:\x1b\[[0-9;?]*[ -/]*[@-~])|(?:\x1b[@-Z\\-_])|(?:\x1b[=>])")

# Env vars that can be used to influence process execution and/or load arbitrary code.
_DEFAULT_DENY_ENV = {
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_PRINT_TO_FILE",
}


def _parse_csv_env(name: str) -> List[str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _now() -> float:
    return time.monotonic()


def _jsonrpc_error(code: int, message: str, id_value: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_value, "error": {"code": code, "message": message}}


def _jsonrpc_success(result: Any, id_value: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_value, "result": result}


def _tool_text(text: str, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


def _get_env_allowlist() -> List[str]:
    return _parse_csv_env("PROC_MCP_ALLOW")


def _get_env_override_allowlist() -> Optional[set[str]]:
    items = _parse_csv_env("PROC_MCP_ENV_ALLOW")
    if not items:
        return None
    return set(items)


def _get_env_override_denylist() -> set[str]:
    deny = set(_DEFAULT_DENY_ENV)
    deny.update(_parse_csv_env("PROC_MCP_ENV_DENY"))
    return deny


def _sanitize_child_env(
    base_env: Dict[str, str],
    overrides: Dict[str, Any],
    *,
    allow: Optional[set[str]],
    deny: set[str],
) -> Tuple[Dict[str, str], List[str]]:
    """
    Merge child env overrides safely.

    - If PROC_MCP_ENV_ALLOW is set: only those keys may be overridden.
    - Denylist always applies (unless explicitly allowed via PROC_MCP_ENV_ALLOW).
    """
    env = dict(base_env)
    rejected: List[str] = []

    for k, v in overrides.items():
        key = str(k)
        # Normalize to avoid accidental bypass via case differences for common keys.
        norm_key = key.upper()

        if allow is not None and key not in allow and norm_key not in allow:
            rejected.append(key)
            continue

        # Denylist blocks by default; allowlist can explicitly opt-in to sensitive keys.
        if allow is None and (norm_key in deny or norm_key.startswith("LD_") or norm_key.startswith("DYLD_")):
            rejected.append(key)
            continue

        env[key] = str(v)

    return env, rejected


def _parse_command_allowlist(items: List[str]) -> Tuple[set[str], set[str]]:
    allowed_names: set[str] = set()
    allowed_paths: set[str] = set()
    for it in items:
        if not it:
            continue
        if "/" in it:
            allowed_paths.add(os.path.realpath(it))
        else:
            allowed_names.add(it)
    return allowed_names, allowed_paths


def _resolve_executable(cmd: str, env: Dict[str, str]) -> Optional[str]:
    if not cmd:
        return None
    if "/" in cmd:
        return os.path.realpath(cmd)
    found = shutil.which(cmd, path=env.get("PATH"))
    if not found:
        return None
    return os.path.realpath(found)


def _is_allowed_exec(
    requested_cmd: str,
    exec_path: str,
    *,
    allowed_names: set[str],
    allowed_paths: set[str],
) -> bool:
    if "*" in allowed_names:
        return True
    if exec_path in allowed_paths:
        return True
    # Basename allowlist applies only when the client asked for a bare name.
    if "/" not in requested_cmd and os.path.basename(requested_cmd) in allowed_names:
        return True
    return False


def _set_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


@dataclass
class Session:
    id: str
    argv: List[str]
    cwd: Optional[str]
    read_fd: int
    write_fd: int
    proc: subprocess.Popen
    created_at: float = field(default_factory=_now)

    _buf: bytearray = field(default_factory=bytearray)
    _buf_lock: threading.Lock = field(default_factory=threading.Lock)
    _has_data: threading.Event = field(default_factory=threading.Event)
    _reader_thread: Optional[threading.Thread] = None
    _closed: bool = False

    def start_reader(self, max_buffer_bytes: int) -> None:
        # Set before starting the thread to avoid races in _drain_once.
        self._max_buffer_bytes = max(1024, int(max_buffer_bytes))

        def _loop() -> None:
            try:
                while True:
                    if self._closed:
                        return
                    if self.proc.poll() is not None:
                        # Still drain anything left.
                        self._drain_once()
                        return
                    if not self._drain_once():
                        time.sleep(0.03)
            finally:
                self._has_data.set()

        self._reader_thread = threading.Thread(target=_loop, name=f"proc-mcp-reader-{self.id}", daemon=True)
        self._reader_thread.start()

    def _drain_once(self) -> bool:
        try:
            rlist, _, _ = select.select([self.read_fd], [], [], 0.0)
        except OSError:
            return False
        if not rlist:
            return False
        try:
            data = os.read(self.read_fd, 65536)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            return False
        if not data:
            return False
        with self._buf_lock:
            self._buf.extend(data)
            if len(self._buf) > self._max_buffer_bytes:
                # Keep tail; drop oldest data.
                drop = len(self._buf) - self._max_buffer_bytes
                del self._buf[:drop]
        self._has_data.set()
        return True

    def write(self, data: bytes) -> int:
        return os.write(self.write_fd, data)

    def unread(self, data: bytes) -> None:
        if not data:
            return
        with self._buf_lock:
            self._buf = bytearray(data) + self._buf
            if len(self._buf) > self._max_buffer_bytes:
                # Drop oldest bytes (at the end) to keep most-recent data.
                del self._buf[self._max_buffer_bytes :]

    def read(self, timeout_ms: int, max_bytes: int, drain: bool) -> bytes:
        if max_bytes <= 0:
            max_bytes = 1024 * 1024
        if timeout_ms < 0:
            timeout_ms = 0
        if timeout_ms:
            # If buffer is empty, wait.
            with self._buf_lock:
                empty = len(self._buf) == 0
            if empty:
                self._has_data.clear()
                self._has_data.wait(timeout_ms / 1000.0)

        with self._buf_lock:
            chunk = bytes(self._buf[:max_bytes])
            if drain and chunk:
                del self._buf[: len(chunk)]
        return chunk

    def close(self, kill: bool = True) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if kill and self.proc.poll() is None:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                except Exception:
                    try:
                        self.proc.terminate()
                    except Exception:
                        pass
                # Reap to avoid zombies.
                try:
                    self.proc.wait(timeout=1.5)
                except Exception:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            self.proc.kill()
                        except Exception:
                            pass
                    try:
                        self.proc.wait(timeout=0.5)
                    except Exception:
                        pass
        finally:
            for fd in {self.read_fd, self.write_fd}:
                try:
                    os.close(fd)
                except Exception:
                    pass


@dataclass
class TmuxSession:
    id: str
    name: str
    argv: List[str]
    cwd: Optional[str]
    width: int
    height: int
    created_at: float = field(default_factory=_now)


class ProcReplMcp:
    def __init__(self) -> None:
        self._initialized = False
        self._sessions: Dict[str, Session] = {}
        self._tmux_sessions: Dict[str, TmuxSession] = {}
        self._base_env: Dict[str, str] = dict(os.environ)
        allow_items = _get_env_allowlist()
        self._allowed_names, self._allowed_paths = _parse_command_allowlist(allow_items)
        self._env_override_allow = _get_env_override_allowlist()
        self._env_override_deny = _get_env_override_denylist()
        self._max_sessions = int(os.environ.get("PROC_MCP_MAX_SESSIONS", "8") or "8")
        self._max_buffer_bytes = int(os.environ.get("PROC_MCP_MAX_BUFFER_BYTES", str(4 * 1024 * 1024)) or str(4 * 1024 * 1024))
        self._hard_max_buffer_bytes = int(os.environ.get("PROC_MCP_MAX_BUFFER_BYTES_HARD", str(16 * 1024 * 1024)) or str(16 * 1024 * 1024))
        self._allow_detach = os.environ.get("PROC_MCP_ALLOW_DETACH", "").strip() in ("1", "true", "yes")
        self._hard_max_io_bytes = int(os.environ.get("PROC_MCP_MAX_IO_BYTES_HARD", str(8 * 1024 * 1024)) or str(8 * 1024 * 1024))
        self._hard_max_timeout_ms = int(os.environ.get("PROC_MCP_MAX_TIMEOUT_MS_HARD", "60000") or "60000")
        self._tmux_keep_on_exit = os.environ.get("PROC_MCP_TMUX_KEEP_ON_EXIT", "").strip() in ("1", "true", "yes")

        # Best-effort cleanup on normal interpreter exit. Doesn't run on SIGKILL.
        atexit.register(self._cleanup)

    def handle(self, req: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(req, dict):
            # JSON-RPC 2.0 Invalid Request uses a null id.
            return _jsonrpc_error(-32600, "Invalid Request: expected object", None)

        method = req.get("method")
        id_value = req.get("id")
        params = req.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        if not isinstance(method, str) or not method:
            return _jsonrpc_error(-32600, "Invalid Request: missing method", id_value)

        if method == "initialize":
            return _jsonrpc_success(self._handle_initialize(params), id_value)

        if method == "notifications/initialized":
            self._initialized = True
            return None

        if not self._initialized:
            return _jsonrpc_error(-32000, "Client must send notifications/initialized before sending requests", id_value)

        if method == "ping":
            return _jsonrpc_success({}, id_value)

        if method == "tools/list":
            return _jsonrpc_success(self._handle_tools_list(params), id_value)

        if method == "tools/call":
            return _jsonrpc_success(self._handle_tools_call(params), id_value)

        if method == "resources/list":
            return _jsonrpc_success({"resources": []}, id_value)

        if method == "resources/templates/list":
            return _jsonrpc_success({"resourceTemplates": []}, id_value)

        if method == "prompts/list":
            return _jsonrpc_success({"prompts": []}, id_value)

        if method == "prompts/get":
            return _jsonrpc_success({}, id_value)

        return _jsonrpc_error(-32601, f"Unknown method: {method}", id_value)

    def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        _ = params  # clientInfo/capabilities are optional; we don't need them.
        return {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "Proc REPL MCP", "version": "0.2.0"},
            "capabilities": {
                "tools": {"listChanged": False},
                "prompts": {"listChanged": False},
                "resources": {},
            },
            "instructions": (
                "Stateful subprocess sessions over a PTY. "
                "Set PROC_MCP_ALLOW (comma-separated, supports '*') to enable commands."
            ),
        }

    def _handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        _ = params
        tools = [
            {
                "name": "open_session",
                "description": "Spawn a stateful subprocess session (PTY by default). Returns a session id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "cwd": {"type": "string"},
                        "env": {"type": "object", "additionalProperties": {"type": "string"}},
                        "pty": {"type": "boolean", "description": "Use a PTY (recommended for interactive tools). Defaults true."},
                        "max_buffer_bytes": {"type": "integer", "description": "Per-session output ring buffer cap."},
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "list_sessions",
                "description": "List active sessions.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "send",
                "description": "Send raw input to a session's stdin.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "data": {"type": "string"},
                        "append_newline": {"type": "boolean", "description": "Defaults true."},
                    },
                    "required": ["session_id", "data"],
                },
            },
            {
                "name": "read",
                "description": "Read accumulated output from a session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "timeout_ms": {"type": "integer", "description": "If buffer is empty, wait up to this time for output."},
                        "max_bytes": {"type": "integer"},
                        "drain": {"type": "boolean", "description": "Drain buffer (default true)."},
                        "strip_ansi": {"type": "boolean", "description": "Strip ANSI escape codes from output."},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "run",
                "description": "Convenience: send a command then read until output is idle.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "command": {"type": "string"},
                        "append_newline": {"type": "boolean", "description": "Defaults true."},
                        "idle_ms": {"type": "integer", "description": "Stop after no new output for this long (default 200ms)."},
                        "until_nul": {"type": "boolean", "description": "Stop after reading a NUL byte (useful for r2/rizin -0 mode)."},
                        "until_regex": {"type": "string", "description": "Stop after regex matches output (regex is applied to raw bytes, utf-8 encoded)."},
                        "strip_nul": {"type": "boolean", "description": "Strip NUL bytes from returned output."},
                        "timeout_ms": {"type": "integer", "description": "Hard timeout (default 5000ms)."},
                        "max_bytes": {"type": "integer", "description": "Max bytes returned (default 1MB)."},
                        "strip_ansi": {"type": "boolean"},
                    },
                    "required": ["session_id", "command"],
                },
            },
            {
                "name": "close_session",
                "description": "Terminate a session and free resources.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "kill": {"type": "boolean", "description": "Defaults true."},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "tmux_open_session",
                "description": "Start a detached tmux session running a command (useful for full-screen TUI apps like vim/htop). Returns a tmux session id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                        "cwd": {"type": "string"},
                        "env": {"type": "object", "additionalProperties": {"type": "string"}},
                        "width": {"type": "integer", "description": "PTY width (columns). Defaults to current terminal width or 120."},
                        "height": {"type": "integer", "description": "PTY height (rows). Defaults to current terminal height or 40."},
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "tmux_list_sessions",
                "description": "List active tmux sessions created by this server.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "tmux_send_keys",
                "description": "Send key tokens to a tmux session's active pane (supports keys like Enter, Escape, C-c, Up, Down).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "keys": {"type": "array", "items": {"type": "string"}, "description": "List of tmux key tokens or literal strings."},
                        "enter": {"type": "boolean", "description": "Append Enter after keys."},
                        "literal": {"type": "boolean", "description": "Use tmux send-keys -l (send literal text)."},
                    },
                    "required": ["session_id", "keys"],
                },
            },
            {
                "name": "tmux_step",
                "description": "Send keys, wait briefly for redraw, then return a pane snapshot (one roundtrip for TUIs).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "keys": {"type": "array", "items": {"type": "string"}, "description": "List of tmux key tokens or literal strings."},
                        "enter": {"type": "boolean", "description": "Append Enter after keys."},
                        "literal": {"type": "boolean", "description": "Use tmux send-keys -l (send literal text)."},
                        "delay_ms": {"type": "integer", "description": "Delay before capture (default 100ms)."},
                        "alternate": {"type": "boolean", "description": "Capture alternate screen (-a). Default false."},
                        "ansi": {"type": "boolean", "description": "Include escape sequences in capture (tmux -e)."},
                        "join": {"type": "boolean", "description": "Join wrapped lines (tmux -J)."},
                        "start_line": {"type": "integer", "description": "Start line for capture (-S). Negative values count from bottom."},
                        "end_line": {"type": "integer", "description": "End line for capture (-E). Negative values count from bottom."},
                        "strip_ansi": {"type": "boolean", "description": "Strip ANSI/VT100 sequences from returned text."},
                    },
                    "required": ["session_id", "keys"],
                },
            },
            {
                "name": "tmux_capture_pane",
                "description": "Capture the current pane contents as text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "alternate": {"type": "boolean", "description": "Capture alternate screen (-a). Default false."},
                        "ansi": {"type": "boolean", "description": "Include escape sequences (tmux -e)."},
                        "join": {"type": "boolean", "description": "Join wrapped lines (tmux -J)."},
                        "start_line": {"type": "integer", "description": "Start line for capture (-S). Negative values count from bottom."},
                        "end_line": {"type": "integer", "description": "End line for capture (-E). Negative values count from bottom."},
                        "strip_ansi": {"type": "boolean", "description": "Strip ANSI/VT100 sequences from returned text."},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "tmux_resize",
                "description": "Resize a tmux session window.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "width": {"type": "integer"},
                        "height": {"type": "integer"},
                    },
                    "required": ["session_id", "width", "height"],
                },
            },
            {
                "name": "tmux_close_session",
                "description": "Kill a tmux session created by this server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "string"}},
                    "required": ["session_id"],
                },
            },
        ]
        return {"tools": tools}

    def _handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name") or params.get("tool")
        args = params.get("arguments") or params.get("args") or {}
        if not isinstance(name, str) or not name:
            return _tool_text("Missing tool name", is_error=True)
        if not isinstance(args, dict):
            return _tool_text("Invalid tool arguments: expected object", is_error=True)

        try:
            if name == "open_session":
                return self._tool_open_session(args)
            if name == "list_sessions":
                return self._tool_list_sessions(args)
            if name == "send":
                return self._tool_send(args)
            if name == "read":
                return self._tool_read(args)
            if name == "run":
                return self._tool_run(args)
            if name == "close_session":
                return self._tool_close_session(args)
            if name == "tmux_open_session":
                return self._tool_tmux_open_session(args)
            if name == "tmux_list_sessions":
                return self._tool_tmux_list_sessions(args)
            if name == "tmux_send_keys":
                return self._tool_tmux_send_keys(args)
            if name == "tmux_step":
                return self._tool_tmux_step(args)
            if name == "tmux_capture_pane":
                return self._tool_tmux_capture_pane(args)
            if name == "tmux_resize":
                return self._tool_tmux_resize(args)
            if name == "tmux_close_session":
                return self._tool_tmux_close_session(args)
        except Exception as e:
            return _tool_text(f"Tool crashed: {e}", is_error=True)

        return _tool_text(f"Unknown tool: {name}", is_error=True)

    def _tool_open_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if len(self._sessions) >= self._max_sessions:
            return _tool_text(f"Too many sessions (limit {self._max_sessions})", is_error=True)

        cmd = args.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            return _tool_text("Missing required parameter: command", is_error=True)

        argv: List[str] = [cmd]
        if isinstance(args.get("args"), list):
            argv += [str(x) for x in args["args"]]

        cwd = args.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            return _tool_text("Invalid cwd (expected string)", is_error=True)

        env = dict(self._base_env)
        if args.get("env") is not None and not isinstance(args.get("env"), dict):
            return _tool_text("Invalid env (expected object of string->string)", is_error=True)
        if isinstance(args.get("env"), dict):
            env, rejected = _sanitize_child_env(
                env,
                args["env"],
                allow=self._env_override_allow,
                deny=self._env_override_deny,
            )
            if rejected:
                return _tool_text(f"env overrides rejected: {', '.join(rejected)}", is_error=True)

        exec_path = _resolve_executable(argv[0], env)
        if not exec_path:
            return _tool_text(f"Command not found: {argv[0]}", is_error=True)
        if not _is_allowed_exec(
            argv[0],
            exec_path,
            allowed_names=self._allowed_names,
            allowed_paths=self._allowed_paths,
        ):
            return _tool_text(
                "Command not allowed. Set PROC_MCP_ALLOW (comma-separated; supports '*'). "
                f"Requested: {argv[0]} (resolved: {exec_path})",
                is_error=True,
            )
        argv[0] = exec_path

        use_pty = args.get("pty")
        if use_pty is None:
            use_pty = True
        use_pty = bool(use_pty)

        max_buf = args.get("max_buffer_bytes")
        if max_buf is None:
            max_buf = self._max_buffer_bytes
        try:
            max_buf = int(max_buf)
        except Exception:
            max_buf = self._max_buffer_bytes
        max_buf = max(1024, min(int(max_buf), int(self._hard_max_buffer_bytes)))

        if use_pty:
            master_fd, slave_fd = pty.openpty()
            _set_nonblocking(master_fd)

            def _preexec() -> None:
                os.setsid()
                try:
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)  # type: ignore[name-defined]
                except Exception:
                    pass

            proc = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=cwd,
                env=env,
                preexec_fn=_preexec,
                close_fds=True,
                text=False,
            )
            os.close(slave_fd)
            read_fd = master_fd
            write_fd = master_fd
        else:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                env=env,
                start_new_session=True,
                close_fds=True,
                text=False,
            )
            if proc.stdout is None or proc.stdin is None:
                return _tool_text("Failed to open pipes", is_error=True)
            read_fd = proc.stdout.fileno()
            write_fd = proc.stdin.fileno()
            _set_nonblocking(read_fd)

        sid = str(uuid.uuid4())
        sess = Session(id=sid, argv=argv, cwd=cwd, read_fd=read_fd, write_fd=write_fd, proc=proc)
        sess.start_reader(max_buffer_bytes=max_buf)
        self._sessions[sid] = sess

        return _tool_text(json.dumps({"session_id": sid, "pid": proc.pid, "argv": argv, "max_buffer_bytes": max_buf}))

    def _tool_list_sessions(self, args: Dict[str, Any]) -> Dict[str, Any]:
        _ = args
        out = []
        for sid, s in list(self._sessions.items()):
            alive = s.proc.poll() is None
            out.append({"session_id": sid, "pid": s.proc.pid, "argv": s.argv, "cwd": s.cwd, "alive": alive})
        return _tool_text(json.dumps(out))

    def _get_session(self, sid: str) -> Optional[Session]:
        s = self._sessions.get(sid)
        if not s:
            return None
        if s.proc.poll() is not None:
            # Keep it visible until user closes, but mark as dead.
            return s
        return s

    def _tool_send(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        data = args.get("data")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        if not isinstance(data, str):
            return _tool_text("Missing required parameter: data", is_error=True)
        s = self._get_session(sid)
        if not s:
            return _tool_text("Unknown session_id", is_error=True)
        if s.proc.poll() is not None:
            return _tool_text("Session already exited", is_error=True)

        append_newline = args.get("append_newline")
        if append_newline is None:
            append_newline = True
        payload = data + ("\n" if append_newline else "")
        written = s.write(payload.encode("utf-8", errors="replace"))
        return _tool_text(json.dumps({"written": written}))

    def _tool_read(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        s = self._get_session(sid)
        if not s:
            return _tool_text("Unknown session_id", is_error=True)

        timeout_ms = int(args.get("timeout_ms") or 0)
        if timeout_ms < 0:
            timeout_ms = 0
        timeout_ms = min(timeout_ms, self._hard_max_timeout_ms)

        max_bytes = int(args.get("max_bytes") or (1024 * 1024))
        if max_bytes <= 0:
            max_bytes = 1024 * 1024
        max_bytes = min(max_bytes, self._hard_max_io_bytes)
        drain = args.get("drain")
        if drain is None:
            drain = True
        drain = bool(drain)

        strip_ansi = bool(args.get("strip_ansi") or False)

        raw = s.read(timeout_ms=timeout_ms, max_bytes=max_bytes, drain=drain)
        text = raw.decode("utf-8", errors="replace")
        if strip_ansi:
            text = ANSI_RE.sub("", text)
        return _tool_text(text)

    def _tool_run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        cmd = args.get("command")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        if not isinstance(cmd, str):
            return _tool_text("Missing required parameter: command", is_error=True)
        s = self._get_session(sid)
        if not s:
            return _tool_text("Unknown session_id", is_error=True)
        if s.proc.poll() is not None:
            return _tool_text("Session already exited", is_error=True)

        append_newline = args.get("append_newline")
        if append_newline is None:
            append_newline = True
        payload = cmd + ("\n" if append_newline else "")

        idle_ms = int(args.get("idle_ms") or 200)
        if idle_ms < 0:
            idle_ms = 0
        idle_ms = min(idle_ms, 5000)

        until_nul = bool(args.get("until_nul") or False)
        until_regex = args.get("until_regex")
        if until_regex is not None and not isinstance(until_regex, str):
            return _tool_text("Invalid until_regex (expected string)", is_error=True)
        if isinstance(until_regex, str) and len(until_regex) > 1024:
            return _tool_text("until_regex too long", is_error=True)

        rx: Optional[re.Pattern[bytes]] = None
        if until_regex:
            try:
                rx = re.compile(until_regex.encode("utf-8"))
            except re.error as e:
                return _tool_text(f"Invalid until_regex: {e}", is_error=True)

        strip_nul = bool(args.get("strip_nul") or False)

        timeout_ms = int(args.get("timeout_ms") or 5000)
        if timeout_ms < 0:
            timeout_ms = 0
        timeout_ms = min(timeout_ms, self._hard_max_timeout_ms)

        max_bytes = int(args.get("max_bytes") or (1024 * 1024))
        if max_bytes <= 0:
            max_bytes = 1024 * 1024
        max_bytes = min(max_bytes, self._hard_max_io_bytes)
        strip_ansi = bool(args.get("strip_ansi") or False)

        # Best-effort: drain any pending output (e.g., startup banners) so run() returns
        # output for *this* command, not earlier noise.
        pre_deadline = _now() + 0.5
        pre_last = _now()
        while _now() < pre_deadline:
            pre = s.read(timeout_ms=30, max_bytes=1024 * 1024, drain=True)
            if pre:
                pre_last = _now()
                continue
            if (_now() - pre_last) >= 0.08:
                break
        s.write(payload.encode("utf-8", errors="replace"))

        deadline = _now() + (timeout_ms / 1000.0)
        last_data = _now()
        buf = bytearray()

        while _now() < deadline and len(buf) < max_bytes:
            if until_nul or rx is not None:
                wait_ms = 50
            else:
                remaining_idle = max(0.0, (idle_ms / 1000.0) - (_now() - last_data))
                wait_ms = int(max(5.0, remaining_idle * 1000.0))

            raw = s.read(timeout_ms=wait_ms, max_bytes=max_bytes - len(buf), drain=True)
            if raw:
                buf.extend(raw)
                last_data = _now()

                if until_nul:
                    idx = buf.find(b"\x00")
                    if idx != -1:
                        remainder = bytes(buf[idx + 1 :])
                        if remainder:
                            s.unread(remainder)
                        del buf[idx:]
                        break

                if rx is not None:
                    m = rx.search(buf)
                    if m is not None:
                        end = m.end()
                        remainder = bytes(buf[end:])
                        if remainder:
                            s.unread(remainder)
                        del buf[end:]
                        break
                continue

            if not until_nul and rx is None:
                if (_now() - last_data) >= (idle_ms / 1000.0):
                    break

        data = bytes(buf)
        text = data.decode("utf-8", errors="replace")
        if strip_ansi:
            text = ANSI_RE.sub("", text)
        if strip_nul:
            text = text.replace("\x00", "")
        return _tool_text(text)

    def _tool_close_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        kill = args.get("kill")
        if kill is None:
            kill = True
        if not bool(kill) and not self._allow_detach:
            # Detaching leaves a background process and can exhaust system resources.
            return _tool_text("kill=false is disabled (set PROC_MCP_ALLOW_DETACH=1 to enable)", is_error=True)
        s = self._sessions.pop(sid, None)
        if not s:
            return _tool_text("Unknown session_id", is_error=True)
        s.close(kill=bool(kill))
        return _tool_text("ok")

    def _tmux_path(self) -> Optional[str]:
        # Do not use client-provided env/PATH. Resolve from server environment.
        return shutil.which("tmux", path=self._base_env.get("PATH"))

    def _tmux_target(self, ts: TmuxSession) -> str:
        # Target the session's active pane (robust to base-index != 0).
        return ts.name

    def _get_tmux_session(self, sid: str) -> Optional[TmuxSession]:
        return self._tmux_sessions.get(sid)

    def _tool_tmux_open_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if os.name == "nt":
            return _tool_text("tmux backend is POSIX-only (macOS/Linux).", is_error=True)

        if (len(self._sessions) + len(self._tmux_sessions)) >= self._max_sessions:
            return _tool_text(f"Too many sessions (limit {self._max_sessions})", is_error=True)

        tmux = self._tmux_path()
        if not tmux:
            return _tool_text("tmux not found in PATH. Install it (macOS: brew install tmux).", is_error=True)

        cmd = args.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            return _tool_text("Missing required parameter: command", is_error=True)

        argv: List[str] = [cmd]
        if isinstance(args.get("args"), list):
            argv += [str(x) for x in args["args"]]

        cwd = args.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            return _tool_text("Invalid cwd (expected string)", is_error=True)

        env_overrides: Dict[str, Any] = {}
        if args.get("env") is not None and not isinstance(args.get("env"), dict):
            return _tool_text("Invalid env (expected object of string->string)", is_error=True)
        if isinstance(args.get("env"), dict):
            env_overrides = args["env"]

        # Validate the requested exec against allowlist. We use a sanitized env to resolve PATH,
        # but by default PATH overrides are denied so resolution stays stable.
        env_for_resolve = dict(self._base_env)
        if env_overrides:
            env_for_resolve, rejected = _sanitize_child_env(
                env_for_resolve,
                env_overrides,
                allow=self._env_override_allow,
                deny=self._env_override_deny,
            )
            if rejected:
                return _tool_text(f"env overrides rejected: {', '.join(rejected)}", is_error=True)

        exec_path = _resolve_executable(argv[0], env_for_resolve)
        if not exec_path:
            return _tool_text(f"Command not found: {argv[0]}", is_error=True)
        if not _is_allowed_exec(
            argv[0],
            exec_path,
            allowed_names=self._allowed_names,
            allowed_paths=self._allowed_paths,
        ):
            return _tool_text(
                "Command not allowed. Set PROC_MCP_ALLOW (comma-separated; supports '*'). "
                f"Requested: {argv[0]} (resolved: {exec_path})",
                is_error=True,
            )
        argv[0] = exec_path

        term_size = shutil.get_terminal_size(fallback=(120, 40))
        width = args.get("width")
        height = args.get("height")
        try:
            width_i = int(width) if width is not None else int(term_size.columns)
        except Exception:
            width_i = int(term_size.columns) if term_size.columns else 120
        try:
            height_i = int(height) if height is not None else int(term_size.lines)
        except Exception:
            height_i = int(term_size.lines) if term_size.lines else 40
        width_i = max(40, min(width_i, 400))
        height_i = max(10, min(height_i, 200))

        sid = str(uuid.uuid4())
        name = f"mcp-{sid.split('-')[0]}"

        tmux_cmd: List[str] = [tmux, "new-session", "-d", "-x", str(width_i), "-y", str(height_i), "-s", name]
        if cwd:
            tmux_cmd += ["-c", cwd]
        # Apply allowed env overrides into the tmux session environment.
        # We pass only overrides via -e to avoid leaking the whole server env.
        for k, v in env_overrides.items():
            tmux_cmd += ["-e", f"{str(k)}={str(v)}"]
        tmux_cmd += argv

        try:
            cp = subprocess.run(tmux_cmd, env=self._base_env, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            return _tool_text("tmux new-session timed out", is_error=True)
        except Exception as e:
            return _tool_text(f"Failed to start tmux session: {e}", is_error=True)

        if cp.returncode != 0:
            msg = (cp.stderr or cp.stdout or "").strip()
            if not msg:
                msg = f"tmux new-session failed (exit {cp.returncode})"
            return _tool_text(msg, is_error=True)

        ts = TmuxSession(id=sid, name=name, argv=argv, cwd=cwd, width=width_i, height=height_i)
        self._tmux_sessions[sid] = ts
        return _tool_text(json.dumps({"session_id": sid, "tmux_name": name, "target": self._tmux_target(ts), "argv": argv, "cwd": cwd, "width": width_i, "height": height_i}))

    def _tool_tmux_list_sessions(self, args: Dict[str, Any]) -> Dict[str, Any]:
        _ = args
        out = []
        for sid, ts in list(self._tmux_sessions.items()):
            out.append(
                {
                    "session_id": sid,
                    "tmux_name": ts.name,
                    "target": self._tmux_target(ts),
                    "argv": ts.argv,
                    "cwd": ts.cwd,
                    "width": ts.width,
                    "height": ts.height,
                    "created_at_s": ts.created_at,
                }
            )
        return _tool_text(json.dumps(out))

    def _tmux_send_keys_impl(self, ts: TmuxSession, keys: List[str], *, enter: bool, literal: bool) -> Optional[str]:
        tmux = self._tmux_path()
        if not tmux:
            return "tmux not found in PATH"

        base_cmd: List[str] = [tmux, "send-keys", "-t", self._tmux_target(ts)]
        if literal:
            base_cmd.append("-l")
        base_cmd += [str(k) for k in keys]

        try:
            cp = subprocess.run(base_cmd, env=self._base_env, capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired:
            return "tmux send-keys timed out"
        except Exception as e:
            return f"tmux send-keys failed: {e}"

        if cp.returncode != 0:
            msg = (cp.stderr or cp.stdout or "").strip()
            if not msg:
                msg = f"tmux send-keys failed (exit {cp.returncode})"
            return msg

        # If using -l, tmux treats "Enter" as literal text, so send it separately without -l.
        if enter:
            try:
                cp2 = subprocess.run([tmux, "send-keys", "-t", self._tmux_target(ts), "Enter"], env=self._base_env, capture_output=True, text=True, timeout=5)
            except subprocess.TimeoutExpired:
                return "tmux send-keys Enter timed out"
            except Exception as e:
                return f"tmux send-keys Enter failed: {e}"
            if cp2.returncode != 0:
                msg = (cp2.stderr or cp2.stdout or "").strip()
                if not msg:
                    msg = f"tmux send-keys Enter failed (exit {cp2.returncode})"
                return msg

        return None

    def _tmux_capture_pane_bytes_impl(
        self,
        ts: TmuxSession,
        *,
        alternate: bool,
        ansi: bool,
        join: bool,
        start_line: Optional[int],
        end_line: Optional[int],
    ) -> Tuple[Optional[bytes], Optional[str]]:
        tmux = self._tmux_path()
        if not tmux:
            return None, "tmux not found in PATH"

        def _run(*, alternate: bool) -> subprocess.CompletedProcess[bytes]:
            cmd: List[str] = [tmux, "capture-pane", "-p", "-t", self._tmux_target(ts)]
            if alternate:
                cmd.append("-a")
            if ansi:
                cmd.append("-e")
            if join:
                cmd.append("-J")
            if start_line is not None:
                cmd += ["-S", str(start_line)]
            if end_line is not None:
                cmd += ["-E", str(end_line)]
            return subprocess.run(cmd, env=self._base_env, capture_output=True, text=False, timeout=5)

        try:
            if alternate:
                cp = _run(alternate=True)
                # Some setups have an alternate screen buffer that exists but is unused/empty.
                # If the result is empty/whitespace-only, fall back to capturing the visible pane.
                if cp.returncode != 0 or not (cp.stdout or b"").strip(b" \t\r\n"):
                    cp = _run(alternate=False)
            else:
                cp = _run(alternate=False)
        except subprocess.TimeoutExpired:
            return None, "tmux capture-pane timed out"
        except Exception as e:
            return None, f"tmux capture-pane failed: {e}"

        if cp.returncode != 0:
            msg = (cp.stderr or b"").decode("utf-8", errors="replace").strip()
            if not msg:
                msg = f"tmux capture-pane failed (exit {cp.returncode})"
            return None, msg

        return cp.stdout or b"", None

    def _tool_tmux_send_keys(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        keys = args.get("keys")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        if not isinstance(keys, list) or not keys:
            return _tool_text("Missing required parameter: keys (array)", is_error=True)

        ts = self._get_tmux_session(sid)
        if not ts:
            return _tool_text("Unknown session_id", is_error=True)

        enter = bool(args.get("enter") or False)
        literal = bool(args.get("literal") or False)

        err = self._tmux_send_keys_impl(ts, [str(k) for k in keys], enter=enter, literal=literal)
        if err:
            return _tool_text(err, is_error=True)
        return _tool_text("ok")

    def _tool_tmux_step(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        keys = args.get("keys")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)
        if not isinstance(keys, list) or not keys:
            return _tool_text("Missing required parameter: keys (array)", is_error=True)

        ts = self._get_tmux_session(sid)
        if not ts:
            return _tool_text("Unknown session_id", is_error=True)

        enter = bool(args.get("enter") or False)
        literal = bool(args.get("literal") or False)
        delay_ms = args.get("delay_ms")
        try:
            delay_ms_i = int(delay_ms) if delay_ms is not None else 100
        except Exception:
            delay_ms_i = 100
        delay_ms_i = max(0, min(delay_ms_i, 5000))

        alternate = bool(args.get("alternate") or False)
        ansi = bool(args.get("ansi") or False)
        join = bool(args.get("join") or False)
        strip_ansi = bool(args.get("strip_ansi") or False)

        start_line = args.get("start_line")
        end_line = args.get("end_line")
        if start_line is not None:
            try:
                start_line = int(start_line)
            except Exception:
                return _tool_text("Invalid start_line (expected integer)", is_error=True)
        if end_line is not None:
            try:
                end_line = int(end_line)
            except Exception:
                return _tool_text("Invalid end_line (expected integer)", is_error=True)

        err = self._tmux_send_keys_impl(ts, [str(k) for k in keys], enter=enter, literal=literal)
        if err:
            return _tool_text(err, is_error=True)

        if delay_ms_i:
            time.sleep(delay_ms_i / 1000.0)

        raw, cap_err = self._tmux_capture_pane_bytes_impl(ts, alternate=alternate, ansi=ansi, join=join, start_line=start_line, end_line=end_line)
        if cap_err:
            return _tool_text(cap_err, is_error=True)
        text = (raw or b"").decode("utf-8", errors="replace")
        if strip_ansi:
            text = ANSI_RE.sub("", text)
        return _tool_text(text)

    def _tool_tmux_capture_pane(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)

        ts = self._get_tmux_session(sid)
        if not ts:
            return _tool_text("Unknown session_id", is_error=True)

        alternate = bool(args.get("alternate") or False)
        ansi = bool(args.get("ansi") or False)
        join = bool(args.get("join") or False)
        strip_ansi = bool(args.get("strip_ansi") or False)

        start_line = args.get("start_line")
        end_line = args.get("end_line")
        if start_line is not None:
            try:
                start_line = int(start_line)
            except Exception:
                return _tool_text("Invalid start_line (expected integer)", is_error=True)
        if end_line is not None:
            try:
                end_line = int(end_line)
            except Exception:
                return _tool_text("Invalid end_line (expected integer)", is_error=True)

        raw, err = self._tmux_capture_pane_bytes_impl(ts, alternate=alternate, ansi=ansi, join=join, start_line=start_line, end_line=end_line)
        if err:
            return _tool_text(err, is_error=True)
        text = (raw or b"").decode("utf-8", errors="replace")
        if strip_ansi:
            text = ANSI_RE.sub("", text)
        return _tool_text(text)

    def _tool_tmux_resize(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)

        ts = self._get_tmux_session(sid)
        if not ts:
            return _tool_text("Unknown session_id", is_error=True)

        tmux = self._tmux_path()
        if not tmux:
            return _tool_text("tmux not found in PATH", is_error=True)

        try:
            width = int(args.get("width"))
            height = int(args.get("height"))
        except Exception:
            return _tool_text("Invalid width/height (expected integers)", is_error=True)
        width = max(40, min(width, 400))
        height = max(10, min(height, 200))

        tmux_cmd: List[str] = [tmux, "resize-window", "-t", ts.name, "-x", str(width), "-y", str(height)]
        try:
            cp = subprocess.run(tmux_cmd, env=self._base_env, capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired:
            return _tool_text("tmux resize-window timed out", is_error=True)
        except Exception as e:
            return _tool_text(f"tmux resize-window failed: {e}", is_error=True)

        if cp.returncode != 0:
            msg = (cp.stderr or cp.stdout or "").strip()
            if not msg:
                msg = f"tmux resize-window failed (exit {cp.returncode})"
            return _tool_text(msg, is_error=True)

        ts.width = width
        ts.height = height
        return _tool_text("ok")

    def _tool_tmux_close_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not isinstance(sid, str) or not sid:
            return _tool_text("Missing required parameter: session_id", is_error=True)

        ts = self._tmux_sessions.pop(sid, None)
        if not ts:
            return _tool_text("Unknown session_id", is_error=True)

        tmux = self._tmux_path()
        if not tmux:
            return _tool_text("tmux not found in PATH", is_error=True)

        tmux_cmd: List[str] = [tmux, "kill-session", "-t", ts.name]
        try:
            cp = subprocess.run(tmux_cmd, env=self._base_env, capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired:
            return _tool_text("tmux kill-session timed out", is_error=True)
        except Exception as e:
            return _tool_text(f"tmux kill-session failed: {e}", is_error=True)

        if cp.returncode != 0:
            # Session might already be gone; treat as error but state is cleaned.
            msg = (cp.stderr or cp.stdout or "").strip()
            if not msg:
                msg = f"tmux kill-session failed (exit {cp.returncode})"
            low = msg.lower()
            if "can't find session" in low or "no such session" in low:
                return _tool_text("ok")
            return _tool_text(msg, is_error=True)

        return _tool_text("ok")

    def _cleanup(self) -> None:
        # Best-effort process cleanup (ignore all errors).
        for sid, s in list(self._sessions.items()):
            try:
                s.close(kill=True)
            except Exception:
                pass
        self._sessions.clear()

        if self._tmux_keep_on_exit:
            return
        tmux = self._tmux_path()
        if not tmux:
            return
        for sid, ts in list(self._tmux_sessions.items()):
            try:
                subprocess.run([tmux, "kill-session", "-t", ts.name], env=self._base_env, capture_output=True, text=True, timeout=2)
            except Exception:
                pass
        self._tmux_sessions.clear()


def main() -> int:
    server = ProcReplMcp()
    max_line = int(os.environ.get("PROC_MCP_MAX_LINE_BYTES", str(256 * 1024)) or str(256 * 1024))

    try:
        while True:
            raw = sys.stdin.buffer.readline()
            if not raw:
                break
            if len(raw) > max_line:
                resp = _jsonrpc_error(-32600, f"Invalid Request: line too large (>{max_line} bytes)", None)
                sys.stdout.write(json.dumps(resp, ensure_ascii=True) + "\n")
                sys.stdout.flush()
                continue

            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                resp = _jsonrpc_error(-32700, "Parse error", None)
                sys.stdout.write(json.dumps(resp, ensure_ascii=True) + "\n")
                sys.stdout.flush()
                continue

            try:
                resp = server.handle(req)
            except Exception:
                # Never crash the server on bad inputs / unexpected edge cases.
                req_id = req.get("id") if isinstance(req, dict) else None
                resp = _jsonrpc_error(-32603, "Internal error", req_id)

            if resp is None:
                continue
            sys.stdout.write(json.dumps(resp, ensure_ascii=True) + "\n")
            sys.stdout.flush()
    finally:
        # Ensure best-effort cleanup on normal exit paths.
        try:
            server._cleanup()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

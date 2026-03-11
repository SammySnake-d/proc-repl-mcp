#!/usr/bin/env python3
"""
Full smoke tests for proc-repl-mcp.

Goal: exercise every tool at least once, plus key failure boundaries, without
depending on any external harness besides Python.

This intentionally favors breadth over deep correctness.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Optional


ROOT = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(ROOT, "server.py")


class Client:
    def __init__(self, proc: subprocess.Popen[str]):
        self.proc = proc
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def send(self, msg: Dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout_s: float = 8.0) -> Dict[str, Any]:
        rid = self._next_id()
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv(rid, timeout_s=timeout_s)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def recv(self, expect_id: Optional[int], timeout_s: float = 8.0) -> Dict[str, Any]:
        assert self.proc.stdout is not None
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                break
            obj = json.loads(line)
            if expect_id is None or obj.get("id") == expect_id:
                return obj
        raise TimeoutError("no response")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})


def _tool_text(resp: Dict[str, Any]) -> str:
    return resp["result"]["content"][0]["text"]


def _tool_is_error(resp: Dict[str, Any]) -> bool:
    return bool(resp["result"].get("isError"))


def _must(resp: Dict[str, Any]) -> None:
    assert "result" in resp and "content" in resp["result"], resp


def main() -> int:
    env = dict(os.environ)
    env["PROC_MCP_ALLOW"] = "python3,cat,sh,vim,r2"
    env.pop("PROC_MCP_ENV_ALLOW", None)
    env.pop("PROC_MCP_ENV_DENY", None)
    env["PROC_MCP_MAX_SESSIONS"] = "4"

    proc = subprocess.Popen(
        [sys.executable, SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    client = Client(proc)

    try:
        client.request("initialize", {"clientInfo": {"name": "full-smoke", "version": "0"}, "capabilities": {}})
        client.notify("notifications/initialized")

        # tools/list should include everything we expose.
        tl = client.request("tools/list", {})
        assert "result" in tl and "tools" in tl["result"], tl
        tool_names = {t["name"] for t in tl["result"]["tools"]}
        expected = {
            "open_session",
            "list_sessions",
            "send",
            "read",
            "run",
            "close_session",
            "tmux_open_session",
            "tmux_list_sessions",
            "tmux_send_keys",
            "tmux_step",
            "tmux_capture_pane",
            "tmux_resize",
            "tmux_close_session",
        }
        missing = expected - tool_names
        assert not missing, f"missing tools: {sorted(missing)}"

        # open_session: basic failure boundaries.
        bad = client.call_tool("open_session", {"command": "echo", "args": ["nope"]})
        assert _tool_is_error(bad), bad

        nf = client.call_tool("open_session", {"command": "definitely-not-a-real-cmd"})
        assert _tool_is_error(nf), nf

        path_override = client.call_tool("open_session", {"command": "python3", "args": ["-q"], "env": {"PATH": "/tmp"}})
        assert _tool_is_error(path_override), path_override

        # open_session: buffer clamp (do not allow huge buffers).
        py = client.call_tool("open_session", {"command": "python3", "args": ["-q"], "max_buffer_bytes": 10**9})
        py_info = json.loads(_tool_text(py))
        py_sid = py_info["session_id"]
        assert py_info["max_buffer_bytes"] <= 16 * 1024 * 1024

        # list_sessions should include the python session.
        sess = client.call_tool("list_sessions", {})
        listed = json.loads(_tool_text(sess))
        assert any(x.get("session_id") == py_sid for x in listed)

        # run(): until_regex for a classic prompt.
        # Note: PTY echo may include the input line; only check for the payload.
        out = client.call_tool(
            "run",
            {
                "session_id": py_sid,
                "command": "print('__PY_OK__')",
                "until_regex": r">>> ",
                "timeout_ms": 5000,
                "strip_ansi": True,
            },
        )
        assert "__PY_OK__" in _tool_text(out)

        # send/read: smoke that data round-trips in PTY mode.
        client.call_tool("send", {"session_id": py_sid, "data": "print('__PY_SEND__')", "append_newline": True})
        seen = False
        deadline = time.time() + 2.0
        buf = ""
        while time.time() < deadline:
            rd = client.call_tool("read", {"session_id": py_sid, "timeout_ms": 250, "strip_ansi": True})
            chunk = _tool_text(rd)
            if chunk:
                buf += chunk
                if "__PY_SEND__" in buf:
                    seen = True
                    break
            time.sleep(0.05)
        assert seen, repr(buf[-400:])

        # close_session: kill=false disabled by default.
        no_detach = client.call_tool("close_session", {"session_id": py_sid, "kill": False})
        assert _tool_is_error(no_detach)
        ok = client.call_tool("close_session", {"session_id": py_sid, "kill": True})
        assert "ok" in _tool_text(ok).lower()

        # Pipe mode regression: cat should echo.
        cat = client.call_tool("open_session", {"command": "cat", "pty": False})
        cat_info = json.loads(_tool_text(cat))
        cat_sid = cat_info["session_id"]
        client.call_tool("send", {"session_id": cat_sid, "data": "hello", "append_newline": True})
        rd2 = client.call_tool("read", {"session_id": cat_sid, "timeout_ms": 500, "strip_ansi": True})
        assert "hello" in _tool_text(rd2)
        client.call_tool("close_session", {"session_id": cat_sid, "kill": True})

        # r2 -0 mode (optional if installed).
        if shutil.which("r2"):
            r2 = client.call_tool("open_session", {"command": "r2", "args": ["-q0", "/bin/ls"], "pty": True})
            r2_sid = json.loads(_tool_text(r2))["session_id"]
            ver = client.call_tool("run", {"session_id": r2_sid, "command": "?V", "until_nul": True, "strip_nul": True, "timeout_ms": 5000})
            assert "radare2" in _tool_text(ver)
            client.call_tool("close_session", {"session_id": r2_sid, "kill": True})

        # tmux backend (optional if installed).
        if shutil.which("tmux"):
            tm = client.call_tool("tmux_open_session", {"command": "sh", "width": 100, "height": 30})
            tm_sid = json.loads(_tool_text(tm))["session_id"]

            ls_tm = client.call_tool("tmux_list_sessions", {})
            listed_tm = json.loads(_tool_text(ls_tm))
            assert any(x.get("session_id") == tm_sid for x in listed_tm)

            # send_keys + capture.
            client.call_tool("tmux_send_keys", {"session_id": tm_sid, "keys": ["echo __TMUX_OK__"], "literal": True, "enter": True})
            cap = client.call_tool("tmux_capture_pane", {"session_id": tm_sid, "strip_ansi": True, "join": True})
            assert "__TMUX_OK__" in _tool_text(cap)

            # tmux_step: one roundtrip.
            cap2 = client.call_tool("tmux_step", {"session_id": tm_sid, "keys": ["echo __TMUX_STEP__"], "literal": True, "enter": True, "delay_ms": 200, "strip_ansi": True, "join": True})
            assert "__TMUX_STEP__" in _tool_text(cap2)

            # resize updates stored width/height.
            client.call_tool("tmux_resize", {"session_id": tm_sid, "width": 120, "height": 35})
            ls2 = client.call_tool("tmux_list_sessions", {})
            listed_tm2 = json.loads(_tool_text(ls2))
            row = next(x for x in listed_tm2 if x.get("session_id") == tm_sid)
            assert row["width"] == 120 and row["height"] == 35

            client.call_tool("tmux_close_session", {"session_id": tm_sid})

            # alternate capture fallback (vim).
            if shutil.which("vim"):
                tv = client.call_tool("tmux_open_session", {"command": "vim", "args": ["-u", "NONE", "-N"], "width": 100, "height": 30})
                tv_sid = json.loads(_tool_text(tv))["session_id"]
                seen_vim = False
                last = ""
                deadline = time.time() + 2.0
                while time.time() < deadline:
                    capv = client.call_tool("tmux_capture_pane", {"session_id": tv_sid, "alternate": True, "strip_ansi": True, "join": True})
                    last = _tool_text(capv)
                    if "VIM - Vi IMproved" in last:
                        seen_vim = True
                        break
                    time.sleep(0.1)
                assert seen_vim, repr(last[:400])
                client.call_tool("tmux_close_session", {"session_id": tv_sid})

            # failure boundary: unknown session id.
            bad2 = client.call_tool("tmux_send_keys", {"session_id": "deadbeef", "keys": ["x"]})
            assert _tool_is_error(bad2)

        # failure boundary: too many sessions.
        a = client.call_tool("open_session", {"command": "python3", "args": ["-q"]})
        b = client.call_tool("open_session", {"command": "python3", "args": ["-q"]})
        c = client.call_tool("open_session", {"command": "python3", "args": ["-q"]})
        d = client.call_tool("open_session", {"command": "python3", "args": ["-q"]})
        assert not _tool_is_error(a)
        assert not _tool_is_error(b)
        assert not _tool_is_error(c)
        assert not _tool_is_error(d)
        e = client.call_tool("open_session", {"command": "python3", "args": ["-q"]})
        assert _tool_is_error(e)

        # Cleanup.
        for resp in (a, b, c, d):
            sid = json.loads(_tool_text(resp))["session_id"]
            client.call_tool("close_session", {"session_id": sid, "kill": True})

        proc.terminate()
        return 0
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=1.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

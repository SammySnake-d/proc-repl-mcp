#!/usr/bin/env python3
"""
Smoke tests for proc-repl-mcp.

Runs the MCP server as a subprocess and speaks line-delimited JSON-RPC over stdio.
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

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rid = self._next_id()
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv(rid)

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def recv(self, expect_id: Optional[int], timeout_s: float = 5.0) -> Dict[str, Any]:
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


def main() -> int:
    env = dict(os.environ)
    env["PROC_MCP_ALLOW"] = "python3,r2,cat,sh"
    # Keep it strict by default: block PATH overrides etc.
    env.pop("PROC_MCP_ENV_ALLOW", None)
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

    # initialize handshake
    client.request("initialize", {"clientInfo": {"name": "smoke", "version": "0"}, "capabilities": {}})
    client.notify("notifications/initialized")

    # Non-object JSON should not crash the server (DoS regression).
    client.send({"jsonrpc": "2.0", "id": 999, "method": "ping"})
    _ = client.recv(999)
    # Now send a raw JSON array line.
    assert proc.stdin is not None
    proc.stdin.write("[]\n")
    proc.stdin.flush()
    # Should respond with Invalid Request and remain alive.
    _ = client.recv(None)
    pong = client.request("ping", {})
    assert "result" in pong

    # PATH override should be rejected by default.
    bad = client.call_tool("open_session", {"command": "python3", "args": ["-q"], "env": {"PATH": "/tmp"}})
    assert _tool_is_error(bad), bad

    # Pipe mode should allow send/read (regression for write-fd bug).
    cat = client.call_tool("open_session", {"command": "cat", "pty": False})
    cat_info = json.loads(_tool_text(cat))
    sid = cat_info["session_id"]
    client.call_tool("send", {"session_id": sid, "data": "hello", "append_newline": True})
    out = client.call_tool("read", {"session_id": sid, "timeout_ms": 500, "strip_ansi": True})
    assert "hello" in _tool_text(out)
    client.call_tool("close_session", {"session_id": sid, "kill": True})

    # r2 -0 mode: run until NUL and ensure it's stripped.
    r2 = client.call_tool("open_session", {"command": "r2", "args": ["-q0", "/bin/ls"], "pty": True})
    r2_info = json.loads(_tool_text(r2))
    r2_sid = r2_info["session_id"]
    ver = client.call_tool("run", {"session_id": r2_sid, "command": "?V", "until_nul": True, "strip_nul": True, "timeout_ms": 5000})
    txt = _tool_text(ver)
    assert "radare2" in txt
    assert "\x00" not in txt
    client.call_tool("close_session", {"session_id": r2_sid, "kill": True})

    # tmux backend: send keys and capture pane (best-effort; skip if tmux not installed).
    if shutil.which("tmux"):
        tm = client.call_tool("tmux_open_session", {"command": "sh", "width": 100, "height": 30})
        assert not _tool_is_error(tm), tm
        tm_info = json.loads(_tool_text(tm))
        tm_sid = tm_info["session_id"]
        cap = client.call_tool(
            "tmux_step",
            {"session_id": tm_sid, "keys": ["echo __MCP_TMUX_TEST__"], "literal": True, "enter": True, "delay_ms": 250, "strip_ansi": True},
        )
        assert "__MCP_TMUX_TEST__" in _tool_text(cap)
        client.call_tool("tmux_close_session", {"session_id": tm_sid})

    # kill=false should be disabled by default.
    py = client.call_tool("open_session", {"command": "python3", "args": ["-q"], "pty": True})
    py_info = json.loads(_tool_text(py))
    py_sid = py_info["session_id"]
    no_detach = client.call_tool("close_session", {"session_id": py_sid, "kill": False})
    assert _tool_is_error(no_detach)
    # still able to close properly
    ok = client.call_tool("close_session", {"session_id": py_sid, "kill": True})
    assert "ok" in _tool_text(ok).lower()

    proc.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

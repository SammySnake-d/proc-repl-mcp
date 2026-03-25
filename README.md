# proc-repl-mcp

Stateful subprocess sessions for MCP (Model Context Protocol).

中文文档: [README.zh.md](README.zh.md)

This server is intentionally small: it keeps a subprocess alive across tool
calls so you can interact with REPL-ish tools (python, r2/rizin, shells) and
optionally drive full-screen TUI programs (vim/htop) via a tmux backend.

## Security

This MCP server is a local RCE capability. By default nothing is allowed unless
you set:

- `PROC_MCP_ALLOW`: comma-separated allowlist of commands (e.g. `python3,r2,sh`)

Env overrides from clients are restricted by default (blocks `PATH`, `LD_*`,
`DYLD_*`, etc). See `PROC_MCP_ENV_ALLOW` / `PROC_MCP_ENV_DENY` in `proc_repl_mcp.py`.

## Tools

- `open_session`, `list_sessions`, `send`, `read`, `run`, `close_session`
- `tmux_open_session`, `tmux_list_sessions`, `tmux_send_keys`, `tmux_step`,
  `tmux_capture_pane`, `tmux_resize`, `tmux_close_session`

## Cursor MCP config (uvx, no manual install)

If you have `uv` installed, you can run this without pre-installing the package:

```json
{
  "mcpServers": {
    "proc-repl-mcp": {
      "command": "uvx",
      "args": ["-q", "-U", "proc-repl-mcp"],
      "env": {
        "PROC_MCP_ALLOW": "*"
      }
    }
  }
}
```

Notes:

- For r2/rizin, use `-0`/`-q0` and `run(until_nul=true)` for reliable message
  boundaries.
- For TUIs, prefer the tmux tools: `tmux_open_session` then `tmux_step` to
  send-keys and capture output in one roundtrip.
- `tmux_send_keys` now sends each key as its own tmux operation and keeps a
  short gap before `Enter`. Tune it with `PROC_MCP_TMUX_KEY_DELAY_MS` if a TUI
  needs slower submission timing.
- `PROC_MCP_ALLOW="*"` enables everything (local RCE). Prefer a strict allowlist
  in real setups.

If `uvx` fails to connect to PyPI in your network, set a mirror index. You can
either pass it via args:

```json
{
  "mcpServers": {
    "proc-repl-mcp": {
      "command": "uvx",
      "args": [
        "-q",
        "-U",
        "--default-index",
        "https://pypi.tuna.tsinghua.edu.cn/simple",
        "proc-repl-mcp"
      ],
      "env": {
        "PROC_MCP_ALLOW": "*"
      }
    }
  }
}
```

Or set it via env (recommended):

```json
{
  "mcpServers": {
    "proc-repl-mcp": {
      "command": "uvx",
      "args": ["-q", "-U", "proc-repl-mcp"],
      "env": {
        "PROC_MCP_ALLOW": "*",
        "UV_DEFAULT_INDEX": "https://pypi.tuna.tsinghua.edu.cn/simple"
      }
    }
  }
}
```

If you haven't published to PyPI yet, you can run directly from GitHub (pin to
a tag or commit):

```json
{
  "mcpServers": {
    "proc-repl-mcp": {
      "command": "uvx",
      "args": [
        "-q",
        "-U",
        "--from",
        "git+https://github.com/SammySnake-d/proc-repl-mcp.git@main",
        "proc-repl-mcp"
      ],
      "env": {
        "PROC_MCP_ALLOW": "*"
      }
    }
  }
}
```

## Install (pip)

```bash
python3 -m pip install proc-repl-mcp
proc-repl-mcp
```

Or run without installing (uvx):

```bash
uvx proc-repl-mcp
```

## Dev

Run smoke tests locally:

```bash
python3 test_smoke.py
python3 test_full_smoke.py
```

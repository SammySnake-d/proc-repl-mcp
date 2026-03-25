# proc-repl-mcp

为 MCP（Model Context Protocol）提供“可保留状态”的子进程会话能力。

核心目标是让 AI 能像 `js_repl` 一样，和本机命令行工具保持长期会话（不需要每次启动/退出），并在需要时通过 tmux 后端驱动 `vim/htop` 这类全屏 TUI 程序。

English README: [README.md](README.md)

## 能力与限制

- 适合：REPL / 命令式工具（`python`、`r2/rizin`、`sh` 等），需要“上下文状态”的交互分析
- 也支持：全屏 TUI（`vim`、`htop` 等），但体验是“快照式”：
  - 发送按键
  - 等待短暂 redraw
  - 抓取当前 pane 文本
- 不适合：追求真正实时流式终端体验的场景（MCP 目前是请求-响应模型）

## 安全边界

这是一个本地 RCE 能力。默认情况下必须显式允许才能运行命令：

- `PROC_MCP_ALLOW`: 逗号分隔的允许命令清单，例如 `python3,r2,sh,vim,htop`

客户端传入的 `env` 覆盖默认是严格受限的（默认阻止 `PATH`、`LD_*`、`DYLD_*` 等可能影响执行/注入的变量）。如需放开，请看 `proc_repl_mcp.py` 中：

- `PROC_MCP_ENV_ALLOW`
- `PROC_MCP_ENV_DENY`

## 提供的 MCP Tools

- 子进程会话：`open_session`, `list_sessions`, `send`, `read`, `run`, `close_session`
- tmux 后端：`tmux_open_session`, `tmux_list_sessions`, `tmux_send_keys`, `tmux_step`, `tmux_capture_pane`, `tmux_resize`, `tmux_close_session`

## Cursor MCP 配置（像 npx 一样自动安装）

推荐用 `uvx`，无需手动安装 Python 包，Cursor 启动 MCP 时会自动拉取并运行：

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

注意：`PROC_MCP_ALLOW="*"` 等于放开全部本机命令执行能力，真实使用建议改成严格白名单。

如果 `uvx` 访问 PyPI 失败（例如 `tls handshake eof`），可以设置镜像索引（推荐用 env）：

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

如果你还没发 PyPI，也可以直接从 GitHub 仓库运行（追最新用 `main`；追稳定建议 pin 到 tag 或 commit）：

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

## 使用建议

- r2/rizin：强烈建议使用 `-0`/`-q0`，并在 `run` 里用 `until_nul=true`，这样服务端可以用 `\\x00` 作为“命令输出结束”的稳定边界。
- TUI：优先用 `tmux_step`，它会在一次调用里完成 `send-keys -> 等待 -> capture-pane`，比客户端手动多次 roundtrip 更稳定。
- `tmux_send_keys` 现在会把每个 key 拆成单独的 tmux 操作，并在提交前保留一个很短的间隔；如果某个 TUI 仍然偏慢，可以用 `PROC_MCP_TMUX_KEY_DELAY_MS` 调大这个间隔。

## 开发与测试

```bash
python3 test_smoke.py
python3 test_full_smoke.py
```

## 许可证

AGPL-3.0（见 [LICENSE](LICENSE)）。

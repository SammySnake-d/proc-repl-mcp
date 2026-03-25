import subprocess
import unittest
from unittest.mock import patch

from proc_repl_mcp import ProcReplMcp, TmuxSession


class TmuxSendKeysTests(unittest.TestCase):
    def test_text_and_enter_are_sent_as_separate_tmux_calls(self) -> None:
        server = ProcReplMcp()
        session = TmuxSession(
            id="sid",
            name="mcp-test",
            argv=["codex", "--no-alt-screen"],
            cwd=None,
            width=120,
            height=40,
        )

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch.object(server, "_tmux_path", return_value="/opt/homebrew/bin/tmux"):
            with patch("proc_repl_mcp.subprocess.run", side_effect=fake_run):
                err = server._tmux_send_keys_impl(session, ["Reply with ONLY DONE", "Enter"], enter=False, literal=False)

        self.assertIsNone(err)
        self.assertEqual(
            calls,
            [
                ["/opt/homebrew/bin/tmux", "send-keys", "-t", "mcp-test", "Reply with ONLY DONE"],
                ["/opt/homebrew/bin/tmux", "send-keys", "-t", "mcp-test", "Enter"],
            ],
        )


if __name__ == "__main__":
    unittest.main()

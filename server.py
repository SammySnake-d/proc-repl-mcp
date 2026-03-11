#!/usr/bin/env python3
"""
Compatibility wrapper for local development/tests.

The published CLI entrypoint is `proc-repl-mcp` (console_script), implemented in
`proc_repl_mcp.py`. These smoke tests expect a `server.py` next to them.
"""

from __future__ import annotations

from proc_repl_mcp import main


if __name__ == "__main__":
    raise SystemExit(main())


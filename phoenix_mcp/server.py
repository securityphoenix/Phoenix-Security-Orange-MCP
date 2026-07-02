"""Phoenix Security MCP server entry point.

Run directly (stdio, for Claude Desktop/Code, Cursor, Codex, ...):
    phoenix-mcp
    python -m phoenix_mcp

Run as a remote HTTP server (for ChatGPT connectors and hosted use):
    phoenix-mcp --transport streamable-http --host 0.0.0.0 --port 8848
    (or PHOENIX_MCP_TRANSPORT=streamable-http)

Requires PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET (and optionally
PHOENIX_API_BASE_URL) in the environment — see docs/INSTALLATION.md.
"""

import argparse
import os
import sys

from phoenix_mcp.core import mcp

# Importing these modules registers all tools on the shared FastMCP app.
import phoenix_mcp.tools_read   # noqa: F401  (read tools)
import phoenix_mcp.tools_write  # noqa: F401  (write tools, honour read-only)

TRANSPORTS = ("stdio", "streamable-http", "sse")


def main():
    parser = argparse.ArgumentParser(
        prog="phoenix-mcp",
        description="Phoenix Security MCP server (API v1.27).")
    parser.add_argument(
        "--transport", choices=TRANSPORTS,
        default=os.environ.get("PHOENIX_MCP_TRANSPORT", "stdio"),
        help="MCP transport (default stdio; streamable-http for remote "
             "clients such as ChatGPT connectors).")
    parser.add_argument("--host",
                        default=os.environ.get("PHOENIX_MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("PHOENIX_MCP_PORT", "8848")))
    args = parser.parse_args()

    missing = [v for v in ("PHOENIX_CLIENT_ID", "PHOENIX_CLIENT_SECRET")
               if not os.environ.get(v)]
    if missing:
        # Credentials are validated lazily per tool call too, but failing
        # fast with a clear message beats 20 broken tool calls later.
        print(
            "phoenix-mcp: missing environment variables: "
            + ", ".join(missing)
            + " (create credentials in Phoenix under Organisation > API "
              "Access; see docs/INSTALLATION.md)",
            file=sys.stderr,
        )
    if args.transport != "stdio":
        # Remote transports carry your Phoenix credentials' power: bind to
        # localhost unless deliberately exposed behind TLS + auth.
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

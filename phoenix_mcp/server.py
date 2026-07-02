"""Phoenix Security MCP server entry point (stdio transport).

Run directly:
    phoenix-mcp
    python -m phoenix_mcp

Requires PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET (and optionally
PHOENIX_API_BASE_URL) in the environment — see docs/INSTALLATION.md.
"""

import os
import sys

from phoenix_mcp.core import mcp

# Importing these modules registers all tools on the shared FastMCP app.
import phoenix_mcp.tools_read   # noqa: F401  (read tools)
import phoenix_mcp.tools_write  # noqa: F401  (write tools, honour read-only)


def main():
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
    mcp.run()


if __name__ == "__main__":
    main()

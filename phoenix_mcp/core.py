"""MCP server core: FastMCP instance, lazy Phoenix client, write guard.

Configuration is environment-based (standard for MCP servers):
    PHOENIX_CLIENT_ID       required
    PHOENIX_CLIENT_SECRET   required
    PHOENIX_API_BASE_URL    optional (default: https://api.securityphoenix.cloud)
    PHOENIX_MCP_READ_ONLY   optional ("true" disables all write tools)
    PHOENIX_MCP_MAX_ITEMS   optional (default cap for list results, 100)
"""

import os

from mcp.server.fastmcp import FastMCP

from phoenix_cli import PhoenixClient
from phoenix_cli.errors import PhoenixError

mcp = FastMCP(
    "Phoenix Security",
    instructions=(
        "Access the Phoenix Security ASPM platform (API v1.27): search "
        "assets and findings (vulnerabilities), read application/component "
        "risk posture, create and enrich assets, enrich findings, manage "
        "applications, components, teams and users. Some operations are "
        "impossible in the Phoenix API — call phoenix_api_gaps to see them "
        "with workarounds instead of guessing."
    ),
)

_client = None


def get_client() -> PhoenixClient:
    global _client
    if _client is None:
        _client = PhoenixClient()  # resolves env vars / config.ini
    return _client


def read_only() -> bool:
    return os.environ.get("PHOENIX_MCP_READ_ONLY", "").strip().lower() in (
        "1", "true", "yes", "on")


def default_max_items() -> int:
    try:
        return int(os.environ.get("PHOENIX_MCP_MAX_ITEMS", "100"))
    except ValueError:
        return 100


def guard_write(operation: str):
    if read_only():
        raise PhoenixError(
            f"'{operation}' blocked: this MCP server is running in read-only "
            "mode (PHOENIX_MCP_READ_ONLY=true). Unset it to allow writes.")


def cap(limit):
    """Clamp requested limits so a tool call can't flood the context."""
    ceiling = default_max_items()
    if not limit or limit <= 0:
        return ceiling
    return min(int(limit), 1000)

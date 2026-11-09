"""MCP server core: FastMCP instance, lazy Phoenix client, write guard.

Configuration is environment-based (standard for MCP servers). Variables are
read from the OS environment; a `.env` file (in the cwd/parents, or
PHOENIX_MCP_ENV_FILE) is loaded as a fallback WITHOUT overriding anything the
MCP client already passed:
    PHOENIX_CLIENT_ID       required
    PHOENIX_CLIENT_SECRET   required
    PHOENIX_API_BASE_URL    optional (default: https://api.securityphoenix.cloud)
    PHOENIX_MCP_READ_ONLY   optional ("true" disables all write tools)
    PHOENIX_MCP_MAX_ITEMS   optional (default cap for list results, 100)
    PHOENIX_MCP_ENV_FILE    optional (explicit path to a .env file)
"""

import os
import posixpath
import re
from urllib.parse import unquote

from mcp.server.fastmcp import FastMCP

from phoenix_cli import PhoenixClient
from phoenix_cli.errors import PhoenixError

from phoenix_mcp.dotenv import load_dotenv

# Best-effort: populate missing env vars from a .env file. Real environment
# variables (e.g. an MCP client's `env` block) always take precedence.
load_dotenv()

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


# Actions that only a person may take, in Phoenix: accepting an autopatcher
# plan by hand and confirming an asset usage. No MCP tool does either, and the
# raw API tool refuses these paths. (Phoenix may still accept an all-auto plan
# by policy at creation when the organisation turned that on.)
PERSON_ONLY_MESSAGE = "this action needs a person in Phoenix"
_PERSON_ONLY_PATHS = (
    re.compile(r"^(/api)?/v1/autopatcher/plans/[^/]+/accept$"),
    re.compile(r"^(/api)?/v1/autopatcher/assets/[^/]+/usage$"),
)


def is_person_only_path(path: str) -> bool:
    """True when ``path`` is a plan-accept or asset-usage route.

    The path part only (``?query`` and ``#fragment`` dropped) is decoded once;
    a ``%`` left after that is refused. Repeated slashes collapse, dot
    segments resolve, a trailing slash and letter case are ignored.
    """
    path = re.split(r"[?#]", path or "", maxsplit=1)[0]
    path = unquote(path)
    if "%" in path:
        return True
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    path = posixpath.normpath(path).rstrip("/").lower()
    return any(rx.match(path) for rx in _PERSON_ONLY_PATHS)


def guard_person_only(path: str):
    if is_person_only_path(path):
        raise PhoenixError(PERSON_ONLY_MESSAGE)

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
from phoenix_cli.config import load_settings
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


NO_API_KEY_MESSAGE = (
    "Phoenix API key not found. This MCP server uses only an API key and "
    "never a stored 'phx login' person token. Set PHOENIX_CLIENT_ID and "
    "PHOENIX_CLIENT_SECRET (Organisation > API Access)."
)


def get_client() -> PhoenixClient:
    global _client
    if _client is None:
        # Resolve env vars / config.ini, then insist on an API key. Without
        # one the CLI transport would fall back to the keychain login token
        # of a person, and an agent could then act as that person.
        settings = load_settings()
        if not (settings.client_id and settings.client_secret):
            raise PhoenixError(NO_API_KEY_MESSAGE)
        _client = PhoenixClient(settings=settings)
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


_SAFE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")


def safe_id(value, name: str = "id", optional: bool = False):
    """Return ``value`` if it is safe to put in a URL path, else raise.

    Accepts only letters, digits, ``_`` and ``-`` (1 to 128 characters, so
    UUIDs fit). Everything else (``/``, ``.``, ``?``, ``%``, spaces, empty
    text, long text) is refused before any HTTP call. ``optional=True`` lets
    ``None`` through for arguments that may be left out.
    """
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise PhoenixError(
            f"invalid {name}: use only letters, digits, '_' and '-' "
            "(1 to 128 characters). Nothing was sent to Phoenix.")
    return value


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


# Allowlist for phoenix_raw_api: only these /v1 routes, nothing else. Person
# only routes (plan accept, usage confirm, device approval under /v1/auth) are
# absent on purpose. The autopatcher routes are listed one by one.
_ALLOWED_PREFIXES = (
    "/v1/applications", "/v1/assets", "/v1/campaigns", "/v1/components",
    "/v1/copilot", "/v1/findings", "/v1/import", "/v1/teams", "/v1/users",
)
_ALLOWED_AUTOPATCHER = (
    re.compile(r"^/v1/autopatcher/policy$"),
    re.compile(r"^/v1/autopatcher/runs$"),
    re.compile(r"^/v1/autopatcher/plans$"),
    re.compile(r"^/v1/autopatcher/plans/[^/]+$"),
    re.compile(r"^/v1/autopatcher/assets/lookup$"),
    re.compile(r"^/v1/autopatcher/assets/[^/]+/(findings|plans|plans/latest-accepted)$"),
)


def is_allowed_path(path: str) -> bool:
    """True only for an ``/v1/...`` route the MCP needs (allowlist)."""
    path = re.split(r"[?#]", path or "", maxsplit=1)[0]
    path = unquote(path)
    if "%" in path or ";" in path or "\\" in path or "://" in path:
        return False
    # A dot segment is never needed. Refuse it before slashes collapse: an
    # HTTP client resolves "a//../b" to "a/b", a different route than the
    # collapsed text "b" this guard would otherwise check.
    if any(seg in (".", "..") for seg in path.split("/")):
        return False
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        return False
    path = posixpath.normpath(path).rstrip("/").lower()
    if path.startswith("/api/"):
        path = path[4:]
    if path.startswith("/v1/autopatcher/"):
        return any(rx.match(path) for rx in _ALLOWED_AUTOPATCHER)
    return any(path == p or path.startswith(p + "/")
               for p in _ALLOWED_PREFIXES)


PLAN_WRITE_MESSAGE = (
    "phoenix_raw_api blocked: only GET is allowed on /v1/autopatcher/plans. "
    "To submit a plan use phoenix_submit_patch_plan (it sends source 'mcp', "
    "which Phoenix never auto-accepts).")
_PLAN_ROUTE = re.compile(
    r"^/v1/autopatcher/(plans|assets/[^/]+/plans)(/.*)?$")


def is_plan_write(method: str, path: str) -> bool:
    """True for a non-GET call on ``/v1/autopatcher/plans`` or below it, or
    on ``/v1/autopatcher/assets/{id}/plans`` or below it.

    Same normalisation as the other guards (one decode, slashes, dot
    segments, case, trailing slash, ``/api`` prefix, ``?``/``#``). A path
    that still holds ``%`` after one decode is treated as a plan route.
    """
    if (method or "").upper() == "GET":
        return False
    path = re.split(r"[?#]", path or "", maxsplit=1)[0]
    path = unquote(path)
    if "%" in path:
        return True
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    path = posixpath.normpath(path).rstrip("/").lower()
    if path.startswith("/api/"):
        path = path[4:]
    return bool(_PLAN_ROUTE.match(path))


def guard_person_only(path: str, method: str = "GET"):
    if is_person_only_path(path):
        raise PhoenixError(PERSON_ONLY_MESSAGE)
    if is_plan_write(method, path):
        raise PhoenixError(PLAN_WRITE_MESSAGE)
    if not is_allowed_path(path):
        raise PhoenixError(
            "phoenix_raw_api blocked: path is not on the allowlist of /v1 "
            "routes this MCP server may call.")

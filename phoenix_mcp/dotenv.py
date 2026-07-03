"""Minimal, dependency-free .env loader.

Loads KEY=VALUE pairs from a .env file into os.environ WITHOUT overriding
variables that are already set (real environment / MCP client `env` blocks
always win). Supports comments (#), blank lines, `export KEY=VALUE`, and
single/double quoted values. This keeps the server usable both ways:
set OS env vars in your MCP client config, OR drop a .env next to the repo.
"""

import os


def find_dotenv(start=None):
    """Search cwd and its parents (up to 4 levels) for a .env file."""
    directory = os.path.abspath(start or os.getcwd())
    for _ in range(5):
        candidate = os.path.join(directory, ".env")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return None


def load_dotenv(path=None, override=False):
    """Load a .env file into os.environ. Returns the dict of keys applied.

    Existing environment variables are preserved unless override=True.
    Never raises on a missing/malformed file — configuration is best-effort.
    """
    path = path or os.environ.get("PHOENIX_MCP_ENV_FILE") or find_dotenv()
    applied = {}
    if not path or not os.path.isfile(path):
        return applied
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return applied
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value
            applied[key] = value
    return applied

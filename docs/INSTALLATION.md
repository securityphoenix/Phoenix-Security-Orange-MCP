# Installation Guide — Phoenix Security MCP Server

Step-by-step installation for every major MCP client.

## Prerequisites

1. **Python 3.10+**
2. **uv** (recommended; provides `uvx`) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
   (alternatives: pipx or plain pip, see below)
3. **Phoenix API credentials** — in the Phoenix platform UI go to
   **Organisation → API Access** and create a credential pair.
   ⚠️ The client secret is displayed **only once** — store it in a secret
   manager.
4. Your **API base URL**:

   | Environment | URL |
   |---|---|
   | SaaS production | `https://api.securityphoenix.cloud` |
   | Demo | `https://api.demo.appsecphx.io` |
   | PoC | `https://api.poc1.appsecphx.io` |
   | Dedicated enterprise | `https://api.<tenant>.securityphoenix.cloud` |

## Option A — uvx (no permanent install, always fresh)

Verify it runs:

```bash
PHOENIX_CLIENT_ID=xxx PHOENIX_CLIENT_SECRET=yyy \
uvx --from git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC phoenix-mcp
```

(The server speaks MCP over stdio — it will wait silently for a client;
Ctrl-C to exit. An immediate credential warning on stderr means env vars are
missing.)

## Option B — pipx / pip (persistent install)

```bash
pipx install git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC
# or: python3 -m pip install git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC
which phoenix-mcp    # note the absolute path for client configs
```

## Option C — from source (development)

```bash
git clone https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC
cd Pheonix-Security-Orange-MPC
uv venv && uv pip install -e ".[dev]"
pytest
```

## Using a .env file

Instead of exporting variables or embedding them in a client config, you can
keep credentials in a `.env` file. The server loads it automatically from the
current directory (or any parent, or `PHOENIX_MCP_ENV_FILE=/path/to/.env`),
and only fills variables that aren't already set — so an MCP client's own
`env` block always wins.

```bash
cp .env.example .env      # then edit .env with your credentials
chmod 600 .env            # keep it private
phoenix-mcp               # picks up .env from this directory
```

`.env` is git-ignored — never commit it. `.env.example` is the safe,
committable template. When launching via `uvx` from an arbitrary directory,
either `cd` into the folder holding `.env` first, or set
`PHOENIX_MCP_ENV_FILE` to its absolute path.

---

## Client configuration

### Claude Code (CLI)

```bash
claude mcp add phoenix-security \
  -e PHOENIX_CLIENT_ID=your-client-id \
  -e PHOENIX_CLIENT_SECRET=your-client-secret \
  -e PHOENIX_API_BASE_URL=https://api.securityphoenix.cloud \
  -- uvx --from git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC phoenix-mcp
```

Scopes: add `--scope user` to enable it in every project, or `--scope project`
to share via `.mcp.json` (never commit real secrets — use `${VAR}` expansion:
`-e PHOENIX_CLIENT_ID='${PHOENIX_CLIENT_ID}'`).

Verify: `claude mcp list` then in a session ask
*"test the phoenix connection"* (runs `phoenix_test_connection`).

### Claude Desktop

1. Settings → **Developer** → **Edit Config** (opens
   `claude_desktop_config.json`):
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
2. Add:

```json
{
  "mcpServers": {
    "phoenix-security": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC",
        "phoenix-mcp"
      ],
      "env": {
        "PHOENIX_CLIENT_ID": "your-client-id",
        "PHOENIX_CLIENT_SECRET": "your-client-secret",
        "PHOENIX_API_BASE_URL": "https://api.securityphoenix.cloud",
        "PHOENIX_MCP_READ_ONLY": "true"
      }
    }
  }
}
```

3. Fully restart Claude Desktop. The tools appear under the 🔌 icon.

> macOS note: if `uvx` isn't found, use its absolute path
> (`which uvx`, typically `~/.local/bin/uvx`) as `command`.

### Cursor

Create `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "phoenix-security": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC", "phoenix-mcp"],
      "env": {
        "PHOENIX_CLIENT_ID": "your-client-id",
        "PHOENIX_CLIENT_SECRET": "your-client-secret",
        "PHOENIX_API_BASE_URL": "https://api.securityphoenix.cloud"
      }
    }
  }
}
```

Enable it under Cursor Settings → MCP.

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "phoenix-security": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC", "phoenix-mcp"],
      "env": {
        "PHOENIX_CLIENT_ID": "${input:phoenix-client-id}",
        "PHOENIX_CLIENT_SECRET": "${input:phoenix-client-secret}"
      }
    }
  }
}
```

### Windsurf / other stdio MCP clients

Any client that launches stdio servers works with:
- **command**: `uvx`
- **args**: `--from git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC phoenix-mcp`
- **env**: the `PHOENIX_*` variables above

If you installed with pipx/pip instead, set **command** to the absolute path
of `phoenix-mcp` and drop the args.

---

## Recommended hardening

- Start with **`PHOENIX_MCP_READ_ONLY=true`**; remove it once you're
  comfortable letting the agent create/enrich assets and findings.
- Use per-purpose API credentials (Phoenix supports multiple credential
  sets) so the MCP server can be revoked independently.
- Keep secrets out of shared configs: prefer OS keychains / env managers,
  and `${VAR}` expansion where the client supports it.
- `PHOENIX_MCP_MAX_ITEMS` (default 100) caps list sizes so a single tool
  call can't flood the model context.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Server doesn't appear in the client | Fully restart the client; check `command` is an absolute path if `uvx` isn't on the client's PATH |
| `missing environment variables` on stderr | The client didn't pass `env` — check the config block placement |
| `Authentication error ... 401` on first tool call | Wrong credentials or wrong `PHOENIX_API_BASE_URL` for those credentials |
| Tool returns `blocked: read-only mode` | Unset `PHOENIX_MCP_READ_ONLY` |
| `spawn uvx ENOENT` (Claude Desktop) | Use the absolute uvx path, or install via pipx and point at `phoenix-mcp` directly |
| Inspecting traffic | `mcp dev phoenix_mcp/server.py` (from a source checkout) opens the MCP Inspector |

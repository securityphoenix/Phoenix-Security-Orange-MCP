# Phoenix Security MCP Server (Orange)

**MCP (Model Context Protocol) server for the [Phoenix Security](https://phoenix.security)
platform.** Give Claude, Cursor, and any MCP-capable AI agent full visibility
into your security posture — assets, vulnerabilities, applications, risk —
with **just an API key**.

Built on the same client library as the
[Phoenix Security CLI](https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI),
covering Phoenix REST API **Enterprise v1.27**.

## What your AI agent can do

**Read / analyse (15 tools)**

- `phoenix_search_findings` — every v1.27 filter: severity, CVE, EPSS, SLA breach, scanner, tags, teams…
- `phoenix_search_assets`, `phoenix_get_asset`, `phoenix_get_finding`
- `phoenix_list_applications`, `phoenix_get_application_posture` — risk buckets, thresholds
- `phoenix_list_components`, `phoenix_get_component_posture`
- `phoenix_list_teams`, `phoenix_get_team_members`, `phoenix_list_users`
- `phoenix_api_gaps` — tells the agent what the API **cannot** do, with workarounds, so it never guesses
- `phoenix_raw_api` — authenticated escape hatch for any `/v1` endpoint
- `phoenix_test_connection`

**Write / automate (16 tools, disable with `PHOENIX_MCP_READ_ONLY=true`)**

- Asset creation & enrichment: `phoenix_create_asset`, `phoenix_enrich_asset`, `phoenix_add_asset_tags`
- Vulnerability enrichment: `phoenix_enrich_finding`, bulk `phoenix_import_assets`
- Structure: `phoenix_create_application`, `phoenix_update_application`, `phoenix_add_application_tags`, `phoenix_create_component`, `phoenix_add_component_rules`, `phoenix_link_repository`
- People: `phoenix_create_team`, `phoenix_add_team_members`, `phoenix_set_team_auto_link_tags`, `phoenix_create_user`, `phoenix_set_users_active`

Example prompts once installed:

> *"Which of my applications have open critical findings breaching SLA? Summarise by team."*
> *"Create a CONTAINER asset for myorg/api:2.1 tagged env:prod and link the org/api repository to the Payments application."*
> *"Enrich CVE-2024-3094 findings with a triage note and raise their severity to 9.8."*

## Quick install

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/) (or pipx/pip).
Create API credentials in Phoenix under **Organisation → API Access**.

### Claude Code

```bash
claude mcp add phoenix-security \
  -e PHOENIX_CLIENT_ID=your-client-id \
  -e PHOENIX_CLIENT_SECRET=your-client-secret \
  -e PHOENIX_API_BASE_URL=https://api.securityphoenix.cloud \
  -- uvx --from git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC phoenix-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json` (Settings → Developer → Edit Config):

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

### Cursor / Windsurf / other MCP clients

Same `command`/`args`/`env` shape in the client's MCP config (e.g.
`.cursor/mcp.json`). Full walkthroughs for every client, plus pipx/pip and
from-source installs: **[docs/INSTALLATION.md](docs/INSTALLATION.md)**.

## AI platform skills

Ready-made skills wrapping this server + the CLI for **Claude, ChatGPT
(Custom GPTs & MCP connectors), OpenAI Codex, and Cursor** — with shared
playbooks for find-asset, find-vulnerability, find-remediation,
exploitable-vulnerabilities, application reports, team risk, and
asset/finding enrichment: **[skills/](skills/)**.

For ChatGPT connectors and other remote clients, the server also runs over
HTTP: `phoenix-mcp --transport streamable-http --port 8848` (keep it behind
TLS + auth; see [skills/chatgpt/README.md](skills/chatgpt/README.md)).

## Configuration

| Environment variable | Required | Description |
|----------------------|----------|-------------|
| `PHOENIX_CLIENT_ID` | ✅ | API client ID (Organisation → API Access) |
| `PHOENIX_CLIENT_SECRET` | ✅ | API client secret (shown once at creation) |
| `PHOENIX_API_BASE_URL` | — | Default `https://api.securityphoenix.cloud`; demo: `https://api.demo.appsecphx.io`; PoC: `https://api.poc1.appsecphx.io`; dedicated: `https://api.<tenant>.securityphoenix.cloud` |
| `PHOENIX_MCP_READ_ONLY` | — | `true` = disable all write tools (recommended to start) |
| `PHOENIX_MCP_MAX_ITEMS` | — | Default cap for list results (default 100) |

## Design notes

- **Clean input/output boundary** — tools accept plain JSON arguments and
  return platform JSON; token handling, retries (`Retry-After` aware),
  pagination and Phoenix payload quirks stay internal.
- **Gaps are flagged, not hidden** — operations the Phoenix API cannot
  perform (per-finding status updates, asset deletion, app deletion, …)
  are exposed through `phoenix_api_gaps` so agents choose the documented
  workaround instead of hallucinating endpoints.
- **Least surprise for writes** — destructive-ish operations honour
  read-only mode; asset/finding writes go through the import pipeline
  exactly like official Phoenix tooling.

## Development

```bash
git clone https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC
cd Pheonix-Security-Orange-MPC
uv venv && uv pip install -e ".[dev]"
pytest                        # offline tests (mocked HTTP)
mcp dev phoenix_mcp/server.py # interactive MCP inspector
```

## License

MIT — see [LICENSE](LICENSE).

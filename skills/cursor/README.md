# Phoenix Security × Cursor

## 1. MCP server

Copy [`mcp.json`](mcp.json) to `.cursor/mcp.json` (project) or
`~/.cursor/mcp.json` (global), fill in your credentials, then enable the
server under **Cursor Settings → MCP**.

## 2. Rule (auto-loaded context)

Copy [`rules/phoenix-security.mdc`](rules/phoenix-security.mdc) to
`.cursor/rules/phoenix-security.mdc`. It is "agent-requested": Cursor loads
it whenever a task mentions security posture, vulnerabilities, CVEs or
Phoenix.

## 3. Slash commands (optional)

Copy the files in [`commands/`](commands/) to `.cursor/commands/` to get
`/phoenix-find-asset`, `/phoenix-find-vuln`, `/phoenix-remediation`,
`/phoenix-exploitable`, `/phoenix-app-report` in the Cursor agent input.

> Tip: never commit real credentials in `.cursor/mcp.json` — use
> placeholders and per-developer local copies, and consider
> `PHOENIX_MCP_READ_ONLY=true` for editor use.

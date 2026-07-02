# Phoenix Security × OpenAI Codex CLI

## 1. Register the MCP server

```bash
codex mcp add phoenix-security \
  --env PHOENIX_CLIENT_ID=your-client-id \
  --env PHOENIX_CLIENT_SECRET=your-client-secret \
  --env PHOENIX_API_BASE_URL=https://api.securityphoenix.cloud \
  -- uvx --from git+https://github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC phoenix-mcp
```

(Equivalent TOML lives in `~/.codex/config.toml` under
`[mcp_servers.phoenix-security]`.) Verify inside Codex with `/mcp`.

Alternatively, skip MCP and let Codex use the CLI directly:
`pipx install git+https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI`
and export the `PHOENIX_*` variables — Codex will shell out to `phx`.

## 2. Teach Codex the playbooks (AGENTS.md)

Append [`AGENTS.md`](AGENTS.md) to your project's `AGENTS.md` (or
`~/.codex/AGENTS.md` for global use).

## 3. Optional slash commands

Copy the prompt files to get `/phoenix-*` commands:

```bash
mkdir -p ~/.codex/prompts && cp prompts/*.md ~/.codex/prompts/
```

| Command | Does |
|---|---|
| `/phoenix-find-asset <query>` | Locate assets by host/IP/image/repo |
| `/phoenix-find-vuln <cve or filter>` | Search findings |
| `/phoenix-remediation <cve or finding>` | Remediation guidance |
| `/phoenix-exploitable` | Currently exploitable OPEN findings |
| `/phoenix-app-report <app name>` | App + assets + vulnerabilities report |

# Phoenix Security — AI Platform Skills

Ready-made skills/instructions that wrap the Phoenix Security **MCP server**
(this repo) and **CLI** ([Phoenix-Security-CLI](https://github.com/Security-Phoenix-demo/Phoenix-Security-CLI))
for the major AI coding assistants.

All platforms share the same canonical playbooks —
[`common/WORKFLOWS.md`](common/WORKFLOWS.md):

1. **find-asset** — locate assets by hostname/IP/image/repo/type
2. **find-vulnerability** — search findings by CVE/severity/app/team
3. **find-remediation** — concrete fixes (`remedy`) with owner context
4. **exploitable-vulnerabilities** — zero-day alerts + high-EPSS OPEN findings, ranked
5. **application-report** — app + posture + components + assets + vulnerabilities
6. **team-risk** — findings by team
7. **create-or-enrich-asset** — attribute-matched upserts via the import pipeline
8. **enrich-finding** — triage via import-merge (the only API write path)
9. **bulk-import** — `new`/`merge`/`delta` semantics
10. **know-the-gaps** — what API v1.27 can't do, with workarounds

## Install per platform

| Platform | Package | Install |
|---|---|---|
| **Claude Code / Claude** | [`claude/phoenix-security/`](claude/phoenix-security/) | `cp -r claude/phoenix-security ~/.claude/skills/` (plus the MCP server: see repo README) |
| **ChatGPT / Custom GPT** | [`chatgpt/`](chatgpt/) | MCP connector (`phoenix-mcp --transport streamable-http`) or Custom GPT + OpenAPI Actions — see its README |
| **OpenAI Codex CLI** | [`codex/`](codex/) | `codex mcp add …` + append `AGENTS.md` + `cp prompts/*.md ~/.codex/prompts/` |
| **Cursor** | [`cursor/`](cursor/) | `.cursor/mcp.json` + `.cursor/rules/phoenix-security.mdc` + `.cursor/commands/` |

Every package teaches the same conventions: severity scales (0–1000 search
vs "1.0"–"10.0" import), EPSS thresholds, OPEN-by-default, result capping,
and the hard rule that API gaps are stated with workarounds — never
improvised endpoints.

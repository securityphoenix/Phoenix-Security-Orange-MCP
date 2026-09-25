---
name: phoenix-security
description: Use when asked about security posture, assets, vulnerabilities, findings, CVEs, remediation, exploitability, risk of applications/teams, or when creating/enriching assets and findings in the Phoenix Security (ASPM) platform — e.g. "find asset", "open critical vulns", "is CVE-X exploitable in our estate", "give me the application's assets and vulnerabilities".
---

# Phoenix Security

## Overview

Query and automate the Phoenix Security platform through the
`phoenix-security` MCP server (34 `phoenix_*` tools) or the `phx` CLI.
Core principle: **use the platform's data, and when the API can't do
something, say so with the documented workaround — never invent endpoints.**

## Prerequisites

- MCP: `phoenix-security` server configured (tools named `phoenix_*`).
- CLI fallback: `phx` on PATH with `PHOENIX_CLIENT_ID`/`PHOENIX_CLIENT_SECRET`
  set (`phx auth test` to verify; `-o json` for machine-readable output).
- If neither responds, stop and ask the user to install one
  (github.com/Security-Phoenix-demo/Pheonix-Security-Orange-MPC).

## Quick reference

| User intent | MCP tool | CLI |
|---|---|---|
| Find asset (host/IP/image/repo) | `phoenix_search_assets` → `phoenix_get_asset` | `phx assets list` / `get` |
| Find vulnerability / CVE | `phoenix_search_findings(cves=[...], status=["OPEN"])` | `phx findings list --cve ...` |
| Remediation for a finding | `phoenix_get_finding` → `data[].remedy` | `phx findings get <id>` |
| Exploitable vulns now | TWO searches on OPEN: one `zero_day_alert=true`, one `epss_score_from="0.5"`; merge + rank | `phx findings list --status OPEN --zero-day`, then `--epss-from 0.5` |
| App + assets + vulns report | posture → components → assets → findings (see workflows.md §5) | `phx apps posture --name ...` |
| Team risk | `phoenix_list_teams` → `phoenix_search_findings(team_ids=[...])` | `phx findings list --team-id ...` |
| Create/enrich asset | `phoenix_create_asset` / `phoenix_enrich_asset` | `phx assets create` / `enrich` |
| Add a new vulnerability | `phoenix_add_finding` (delta — never closes others) | `phx findings add` |
| Close a vulnerability | `phoenix_close_finding(finding_id, assessment_name)` — merge workaround, `dry_run` first | `phx findings close <id> --assessment ...` |
| Triage/enrich finding | `phoenix_enrich_finding` (import-merge) | `phx findings enrich` |
| Edit asset (additive) | `phoenix_update_asset` — cannot remove attrs/delete | `phx assets update` |
| Remove asset tags | `phoenix_remove_asset_tags` — scanner/import ownership is protected | `phx assets remove-tags` |
| Anything unusual | check `phoenix_api_gaps` FIRST | `phx gaps` |

Full step-by-step workflows, severity/EPSS conventions and required asset
attributes: [references/workflows.md](references/workflows.md).

## Rules

- Severity scale in searches is **0–1000** (critical ≥ 900, high ≥ 700);
  import severity is a string `"1.0"`–`"10.0"`. Don't mix them.
- Always filter `status=["OPEN"]` unless the user asks about closed/history.
- Cap list sizes (`limit`) and summarise; never dump raw pages of JSON.
- Writes: prefer `delta`/merge semantics as implemented by the tools;
  re-running asset creation is a safe upsert (attribute matching).
- Finding status changes, severity overrides, comments, asset/app deletion
  are **impossible via API v1.27** — consult `phoenix_api_gaps` and offer
  the workaround instead.

## Common mistakes

- Inventing endpoints for gaps (e.g. "PATCH /v1/findings") — run
  `phoenix_api_gaps` and relay the workaround.
- Treating a 404 as "doesn't exist" — Phoenix also returns 404 when the
  credentials lack access; mention both possibilities.
- Using UI severity (0–10) values in `severity_score_from` (0–1000 scale).
- Forgetting `assessment_name` context when enriching findings — merge
  imports operate within an assessment scope.
- Enriching a finding with a changed `name` — the merge matches findings by
  name and would CREATE a new finding. Start from `phoenix_get_finding` to
  recover the exact name and `assetId` → `phoenix_get_asset` → attributes.
- Treating CONTAINER's `dockerfile` attribute as a file path — it carries
  the image reference (e.g. `myorg/checkout:2.0`).

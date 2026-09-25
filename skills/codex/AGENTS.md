# Phoenix Security (ASPM) — agent guidance

Use the `phoenix-security` MCP tools (`phoenix_*`) when configured, else the
`phx` CLI (`phx --help`; add `-o json` for parsing; `phx auth test` checks
credentials).

Conventions: finding-search severity is 0–1000 (critical ≥ 900, high ≥ 700);
import/write severity is a string "1.0"–"10.0"; EPSS ≥ 0.5 = likely
exploited; default to `status OPEN`; keep limits ≤ 100 and summarise.

Playbooks:
- **Find asset**: `phoenix_search_assets` / `phx assets list --type ...`;
  match hostname/IP/image/repo via asset `key`/`attributes`/`tags`.
- **Find vulnerability**: `phoenix_search_findings` / `phx findings list`
  with `--cve`, `--status OPEN`, `--severity-from`, `--app-env-id`.
- **Remediation**: get the finding; the fix is `data[].remedy`, location in
  `location`, owner app/component in `parents[]`.
- **Exploitable now**: OPEN findings with `zero_day_alert=true`, plus
  `epss_score_from 0.5` (optionally severity ≥ 700); rank EPSS × severity,
  flag exposed/EXTERNAL assets.
- **App report**: resolve app → posture (`phx apps posture --name`) →
  components (`--parent-id`) → assets (`--app-env-id`) → OPEN findings →
  summarise with a remediation shortlist.
- **Create/enrich asset**: `phoenix_create_asset` / `phx assets create`
  (INFRA needs ip+hostname; CLOUD providerType+providerAccountId;
  CONTAINER `dockerfile` = the image reference, e.g. `myorg/api:2.0`;
  REPOSITORY repository). Re-running is a safe upsert.
- **Enrich finding**: import-merge only (`phoenix_enrich_finding` /
  `phx findings enrich`) — needs asset attributes + name/description/
  remedy/severity. From a finding ID: get the finding → exact `data[].name`
  + `assetId` → get the asset → use its attributes. A changed name CREATES
  a new finding instead of updating.

Hard API limits (v1.27) — do NOT invent endpoints: no finding status
change/severity override/comments, no asset delete, no app or
team delete, no user delete/role change. Check `phoenix_api_gaps` /
`phx gaps` and offer the documented workaround.

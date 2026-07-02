# Phoenix Security — Canonical Agent Workflows

The shared playbook behind every platform skill in this directory. Each
workflow lists the **MCP tool calls** (for Claude, Cursor, Codex, ChatGPT
connectors) and the equivalent **CLI commands** (`phx`, for shell-capable
agents and CI).

Severity/exploitability conventions used throughout:
- `severityScore` (search scale): 0–1000. Critical ≥ 900, High ≥ 700.
- `epssScore`: 0.0–1.0 exploit-prediction probability. ≥ 0.5 = likely
  exploited; ≥ 0.1 already worth attention.
- Import `severity` (write scale): string `"1.0"`–`"10.0"`.

---

## 1. find-asset

Locate assets by hostname, IP, repository, container image, cloud account or
type.

**MCP**: `phoenix_search_assets(types=[...], limit=...)`, then narrow:
scope with `application_environment_id` / `component_service_id` (get IDs
from `phoenix_list_applications` / `phoenix_list_components`). Inspect one
asset with `phoenix_get_asset(asset_id)`.

**CLI**:
```bash
phx assets list --type INFRA --limit 50 -o json
phx assets list --type CONTAINER --app-env-id <uuid>
phx assets get <asset-id>
```

Matching tips: asset `key` carries the natural identifier (hostname/IP,
image, repo). Filter client-side on `key`, `tags` and `attributes` when the
API-side filters are too coarse.

ID note: Applications and Environments share one ID space
(`/v1/applications`); the `id` field from `phoenix_list_applications` /
`phx apps list` is exactly what `application_environment_id` expects.

## 2. find-vulnerability

Find findings by CVE, severity, application, status, scanner or tag.

**MCP**: `phoenix_search_findings(cves=["CVE-..."], status=["OPEN"],
severity_score_from="700", application_environment_id=..., limit=...)`;
details via `phoenix_get_finding(finding_id)`.

**CLI**:
```bash
phx findings list --cve CVE-2024-3094 --status OPEN -o json
phx findings list --app-env-id <uuid> --severity-from 900
phx findings get <finding-id>
```

## 3. find-remediation

Get the fix for a finding (or a CVE across the estate).

1. Find the finding(s) — workflow 2.
2. `phoenix_get_finding` / `phx findings get <id>`: the **`data[].remedy`**
   field is the remediation; `data[].description` explains the issue;
   `data[].cve` + `tags` give references; `location` says where to fix.
3. Report remedy + affected asset (`assetId` → workflow 1 for asset detail)
   + owning application/component (`parents[]`).

## 4. exploitable-vulnerabilities

Surface what is most likely to be exploited **right now**.

**MCP** (TWO separate searches — do not AND the filters into one call —
then merge, dedupe and rank):
- `phoenix_search_findings(status=["OPEN"], zero_day_alert=true)` — active
  zero-day alerts first.
- `phoenix_search_findings(status=["OPEN"], epss_score_from="0.5")` — high
  exploit probability.
- Optionally add `severity_score_from="700"` and rank by
  `epssScore * severityScore`, flagging `exposed: true` and
  `assetLocality: EXTERNAL/DMZ` findings.

**CLI**:
```bash
phx findings list --status OPEN --zero-day -o json
phx findings list --status OPEN --epss-from 0.5 --severity-from 700 -o json
```

Report: finding, CVE, EPSS, severity, exposure, asset, owning app, remedy.

## 5. application-report ("give me application, assets and vulnerabilities")

Full picture of one application/environment.

1. Resolve the app: `phoenix_list_applications` (match name) or
   `phx apps list`.
2. Posture: `phoenix_get_application_posture(name=...)` /
   `phx apps posture --name "..."` — risk, threshold, open findings by
   bucket, asset count.
3. Structure: `phoenix_list_components(parent_id=<app-id>)` /
   `phx components list --parent-id <id>`.
4. Assets: `phoenix_search_assets(application_environment_id=<app-id>)` /
   `phx assets list --app-env-id <id>`.
5. Vulnerabilities: `phoenix_search_findings(
   application_environment_id=<app-id>, status=["OPEN"])` /
   `phx findings list --app-env-id <id> --status OPEN`.
6. Summarise: posture → riskiest components → top findings (severity/EPSS)
   → remediation shortlist.

## 6. team-risk

Risk view for a team: `phoenix_list_teams` → `phoenix_search_findings(
team_ids=[...], status=["OPEN"])`; members via `phoenix_get_team_members`.
CLI: `phx teams list`, `phx findings list --team-id <uuid> --status OPEN`.

## 7. create-or-enrich-asset

**Create** (upsert — matched by attributes, safe to re-run):
`phoenix_create_asset(asset_type, attributes, tags)`

```bash
phx assets create --type INFRA --attr ip=10.0.0.1 --attr hostname=web-01 --tag env:prod
phx assets create --type CONTAINER --attr dockerfile=myorg/checkout:2.0 --tag team:payments
```

Required attributes: INFRA `ip`+`hostname` · WEB `ip` or `fqdn` · CLOUD
`providerType`+`providerAccountId` (+`region` for Azure) · CONTAINER
`dockerfile` · REPOSITORY `repository` · BUILD `buildFile` · CODE
`scannerSource`.

Note: for CONTAINER assets the `dockerfile` attribute carries the **image
reference** (e.g. `myorg/checkout:2.0`) — despite the name, it is not a
file path. Numeric-looking filter values (`severity_score_from`,
`epss_score_from`, import `severity`) are passed as **strings**; tags are
flat `"key:value"` strings.

**Enrich**: `phoenix_enrich_asset` / `phx assets enrich` (same matching
attributes + new attributes/tags/installedSoftware). Tag-only with a known
ID: `phoenix_add_asset_tags` / `phx assets tag`.

## 8a. add-finding

Add a brand-new vulnerability to an asset (created if absent):
`phoenix_add_finding(asset_type, asset_attributes, finding)` /
`phx findings add --asset-type CONTAINER --asset-attr dockerfile=org/api:1.0
--name ... --description ... --remedy ... --severity 8.5`.
Uses import `delta` — never closes or alters other findings.

## 8b. close-finding

Close a finding — WORKAROUND (no close endpoint exists; it's on the
required-endpoints list): `phoenix_close_finding(finding_id,
assessment_name, dry_run=true)` / `phx findings close <id> --assessment
"..." --dry-run`. Mechanism: re-imports the finding's asset within the SAME
assessment via merge, re-sending its other OPEN findings and omitting the
target, which Phoenix then closes. `assessment_name` MUST be the assessment
that owns the finding. Always dry-run first and show the user what will be
re-imported.

## 8. enrich-finding (triage)

The ONLY finding write path is import-merge (no per-finding update API):
`phoenix_enrich_finding(asset_type, asset_attributes, finding={name,
description, remedy, severity, tags, details}, assessment_name=...)` /
`phx findings enrich --asset-type ... --asset-attr ... --name ... --severity 9.8 --tag triaged:true --assessment ...`

Starting from a finding ID: `phoenix_get_finding(id)` → take the finding's
`data[].name` and `assetId` → `phoenix_get_asset(assetId)` → use its
`attributes` as the matching `asset_attributes`. The finding `name` must
match the originally imported name exactly, or the merge creates a NEW
finding instead of updating. Pass `assessment_name` matching the original
import when known (finding `origin`/assessment context).

Use `details` (JSON) for triage notes. Status/risk-accept/false-positive
are **not possible via API** — say so instead of inventing calls.

## 9. bulk-import

`phoenix_import_assets(import_type, assessment_name, asset_type, assets)` /
`phx import file payload.json`. **`delta` never closes findings** (safest);
`merge`/`new` close findings absent from the payload. Templates:
`phx import template INFRA|CONTAINER|CLOUD`.

## 10. know-the-gaps

Before any unusual write, check `phoenix_api_gaps` / `phx gaps`. Not
possible in API v1.27: finding status changes, severity overrides, comments;
asset delete / tag removal / direct attribute edit; app/env delete; team
delete; user delete or role change; scanner-type listing. Each has a
documented workaround — use it, never fabricate an endpoint.

Common workaround one-liners (full detail in the gaps tool output):
- Close/false-positive/risk-accept a finding → platform UI; or annotate via
  enrich-finding with a tag like `false-positive:candidate` + `details` note.
- Auto-close findings → omit them from a `merge`/`new` import of the same
  assessment.
- Delete asset/app/team/user → platform UI only (deactivate users via API).

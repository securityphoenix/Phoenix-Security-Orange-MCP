"""Read-only MCP tools: search, retrieve, posture, inventory, gap registry."""

from typing import Optional

from phoenix_mcp.core import cap, get_client, mcp, safe_id


@mcp.tool()
def phoenix_test_connection() -> dict:
    """Verify Phoenix API credentials and connectivity. Returns the target
    environment and how many applications/environments are visible."""
    return get_client().test_connection()


@mcp.tool()
def phoenix_search_assets(
    types: Optional[list[str]] = None,
    application_environment_id: Optional[str] = None,
    component_service_id: Optional[str] = None,
    only_unassigned: Optional[bool] = None,
    limit: Optional[int] = None,
) -> list:
    """Search the Phoenix asset registry.

    types: asset types to include — INFRA, CLOUD, WEB, CONTAINER, REPOSITORY,
    BUILD, CODE. Scope with application_environment_id or
    component_service_id (Phoenix UUIDs). only_unassigned=true returns assets
    not assigned to any environment.
    """
    return get_client().search_assets(
        types=types,
        application_environment_id=application_environment_id,
        component_service_id=component_service_id,
        only_unassigned=only_unassigned,
        max_items=cap(limit),
    )


@mcp.tool()
def phoenix_get_asset(asset_id: str) -> dict:
    """Get one asset by its Phoenix ID (UUID), including attributes per
    scanner source and tags."""
    return get_client().get_asset(safe_id(asset_id, "asset_id"))


@mcp.tool()
def phoenix_search_findings(
    application_environment_id: Optional[str] = None,
    component_service_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    finding_type: Optional[str] = None,
    status: Optional[list[str]] = None,
    severity_score_from: Optional[str] = None,
    severity_score_to: Optional[str] = None,
    cves: Optional[list[str]] = None,
    epss_score_from: Optional[str] = None,
    scanner_types: Optional[list[str]] = None,
    tag_keys: Optional[list[str]] = None,
    tag_values: Optional[list[str]] = None,
    team_ids: Optional[list[str]] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    sla_breach: Optional[str] = None,
    zero_day_alert: Optional[bool] = None,
    limit: Optional[int] = None,
) -> list:
    """Search findings (vulnerabilities) with Phoenix v1.27 filters.

    finding_type: WEB|CLOUD|FOSS|SAST|CONTAINER|INFRA. status: OPEN/CLOSED.
    severity_score_from/to: 0-1000 scale. cves: values starting 'CVE-'.
    date_from/to: yyyy-MM-dd. sla_breach: "true"|"false".
    Returns finding objects incl. severityScore, location, assetId, parents
    (application/component), SLA policy and workflow tickets.
    """
    return get_client().search_findings(
        application_environment_id=application_environment_id,
        component_service_id=component_service_id,
        asset_id=asset_id,
        finding_type=finding_type,
        status=status,
        severity_score_from=severity_score_from,
        severity_score_to=severity_score_to,
        cves=cves,
        epss_score_from=epss_score_from,
        scanner_types=scanner_types,
        tag_keys=tag_keys,
        tag_values=tag_values,
        team_ids=team_ids,
        date_from=date_from,
        date_to=date_to,
        sla_breach=sla_breach,
        zero_day_alert=zero_day_alert,
        max_items=cap(limit),
    )


@mcp.tool()
def phoenix_get_finding(finding_id: str) -> dict:
    """Get one finding (vulnerability) by its Phoenix ID, including CVE data,
    SLA policy, workflow tickets and tags."""
    return get_client().get_finding(safe_id(finding_id, "finding_id"))


@mcp.tool()
def phoenix_list_applications(
    entity_type: Optional[str] = None,
    limit: Optional[int] = None,
) -> list:
    """List applications and environments with risk, criticality, threshold
    and finding stats. entity_type: APPLICATION or ENVIRONMENT (omit for both)."""
    return get_client().list_applications(entity_type=entity_type,
                                          max_items=cap(limit))


@mcp.tool()
def phoenix_get_application(application_id: str) -> dict:
    """Get one application/environment by Phoenix ID."""
    return get_client().get_application(safe_id(application_id, "application_id"))


@mcp.tool()
def phoenix_get_application_posture(
    application_id: Optional[str] = None,
    name: Optional[str] = None,
    exclude_risk_accepted: Optional[bool] = None,
) -> dict:
    """Risk posture for an application/environment: open/closed findings by
    risk bucket (critical/high/medium/low/none), asset totals, risk score and
    threshold. Identify by Phoenix ID or by name."""
    return get_client().get_application_posture(
        application_id=safe_id(application_id, "application_id", optional=True), name=name,
        exclude_risk_accepted=exclude_risk_accepted)


@mcp.tool()
def phoenix_list_components(
    parent_id: Optional[str] = None,
    entity_type: Optional[str] = None,
    limit: Optional[int] = None,
) -> list:
    """List components (of applications) and services (of environments).
    parent_id scopes to one application/environment. entity_type:
    COMPONENT or SERVICE.

    effectiveExposure (INTERNAL|DMZ|EXTERNAL) is the exposure Phoenix
    calculated, or the declared exposure if none has been calculated yet."""
    return get_client().list_components(parent_id=parent_id,
                                        entity_type=entity_type,
                                        max_items=cap(limit))


@mcp.tool()
def phoenix_get_component_posture(
    component_id: Optional[str] = None,
    app_name: Optional[str] = None,
    component_name: Optional[str] = None,
    exclude_risk_accepted: Optional[bool] = None,
) -> dict:
    """Risk posture for one component/service. Identify by component_id, or
    by app_name + component_name."""
    return get_client().get_component_posture(
        component_id=safe_id(component_id, "component_id", optional=True), app_name=app_name,
        component_name=component_name,
        exclude_risk_accepted=exclude_risk_accepted)


@mcp.tool()
def phoenix_list_teams(limit: Optional[int] = None) -> list:
    """List teams (id, name, type GENERAL/SECURITY, member count)."""
    return get_client().list_teams(max_items=cap(limit))


@mcp.tool()
def phoenix_get_team_members(team_id: str) -> list:
    """List the members (id, email) of a team."""
    return get_client().get_team_members(safe_id(team_id, "team_id"))


@mcp.tool()
def phoenix_list_users(limit: Optional[int] = None) -> list:
    """List organisation users (id, email, name, role, active)."""
    return get_client().list_users(max_items=cap(limit))


@mcp.tool()
def phoenix_get_campaign_stats(campaign_id: str) -> dict:
    """Aggregated statistics for a campaign by its Phoenix ID (UUID): risk and
    riskMagnitude, finding/asset counts, outside-SLA count, ticket summary and
    severity breakdown (findingStats). Read-only. `stats` may be null if no
    daily snapshot has been generated for the campaign yet."""
    return get_client().get_campaign_stats(safe_id(campaign_id, "campaign_id"))


@mcp.tool()
def phoenix_api_gaps() -> dict:
    """List operations that are NOT possible in Phoenix API v1.27 (finding
    status updates, asset deletion, app deletion, ...) with the recommended
    workaround for each, plus requiredEndpoints — the endpoints the API
    should add. Consult this before attempting an unusual write."""
    from phoenix_cli.gaps import GAPS, REQUIRED_ENDPOINTS
    return {"gaps": GAPS, "requiredEndpoints": REQUIRED_ENDPOINTS}


@mcp.tool()
def phoenix_raw_api(
    method: str,
    path: str,
    json_body: Optional[dict] = None,
) -> dict:
    """Escape hatch: call an allowlisted Phoenix /v1 API path directly
    (authenticated, retried; any other path is refused). method: GET|POST|PUT|PATCH|DELETE. Respects read-only mode for
    non-GET methods. Refuses the routes that accept an autopatcher plan or
    confirm an asset usage: a person does that in Phoenix. Only GET is allowed
    on /v1/autopatcher/plans (use phoenix_submit_patch_plan to submit one). Prefer the
    dedicated tools when one exists."""
    from phoenix_mcp.core import guard_person_only, guard_write
    method = method.upper()
    guard_person_only(path, method)
    if method != "GET":
        guard_write(f"raw {method} {path}")
    result = get_client().raw_request(method, path, json_body=json_body)
    return result if result is not None else {"status": "ok (no content)"}


# -- autopatcher and Copilot patch plans (read-only) ---------------------------

@mcp.tool()
def phoenix_asset_lookup(
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
) -> dict:
    """Read-only. Find the Phoenix assets that match a host name (or FQDN)
    and/or an IP address. Give at least one. Returns up to 20 matches, each
    with assetId, name, os, ips, tags, lastScanAt and matchedBy. Needs the
    autopatcher feature switched on for the organisation."""
    return get_client().lookup_asset(hostname=hostname, ip=ip)


@mcp.tool()
def phoenix_patch_policy(usage: str) -> dict:
    """Read-only. The patch policy for an asset usage (for example server or
    developer-laptop): rules per action type, blocked commands and software,
    and package groups. Needs the autopatcher feature."""
    return get_client().get_patch_policy(usage)


@mcp.tool()
def phoenix_patch_plan(plan_id: str) -> dict:
    """Read-only. One autopatcher plan by ID: its state (PENDING_ACCEPTANCE or
    ACCEPTED), hash, actions and expiry. A plan runs only once it is
    ACCEPTED: by a person in Phoenix, or by Phoenix itself at creation when
    automatic acceptance is on for the asset's usage and every action is auto
    (then no person has seen it)."""
    return get_client().get_patch_plan(safe_id(plan_id, "plan_id"))


@mcp.tool()
def phoenix_latest_accepted_patch_plan(asset_id: str) -> dict:
    """Read-only. The newest accepted, unexpired autopatcher plan for an
    asset. Returns {"plan": null, "reason": "NO_VALID_PLAN"} when there is
    none."""
    plan = get_client().get_latest_accepted_plan(safe_id(asset_id, "asset_id"))
    if plan is None:
        return {"plan": None, "reason": "NO_VALID_PLAN"}
    return plan


@mcp.tool()
def phoenix_copilot_job_status(job_id: str) -> dict:
    """Read-only. State of a Copilot patch plan job: RUNNING, DONE or FAILED.
    When DONE it carries the planId to read with
    phoenix_copilot_patch_plan."""
    return get_client().get_job(safe_id(job_id, "job_id"))


@mcp.tool()
def phoenix_copilot_patch_plan(plan_id: str) -> dict:
    """Read-only. A patch plan written by Copilot, by the planId from
    phoenix_copilot_job_status: actions, finding IDs, hash, state and expiry.
    A person accepts it in Phoenix before anything runs, unless the
    organisation turned on automatic acceptance for the asset's usage and
    every action is auto: then Phoenix accepted it at creation with no
    person."""
    return get_client().get_copilot_patch_plan(safe_id(plan_id, "plan_id"))


@mcp.tool()
def phoenix_autopatch_findings(asset_id: str, page: int = 0) -> dict:
    """Read-only. One page of the open findings of an asset, for patch
    planning: id, title, remedyText, product, fixedVersion, versionOperator.
    Pages start at 0; the page size follows PHOENIX_MCP_MAX_ITEMS (default
    100). The reply carries page, size and total, so call again with the next
    page until you have them all."""
    asset_id = safe_id(asset_id, "asset_id")
    size = min(cap(None), 1000)
    return get_client().raw_request(
        "GET", f"/v1/autopatcher/assets/{asset_id}/findings",
        params={"page": max(int(page), 0), "size": size})

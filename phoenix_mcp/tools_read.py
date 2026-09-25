"""Read-only MCP tools: search, retrieve, posture, inventory, gap registry."""

from typing import Optional

from phoenix_mcp.core import cap, get_client, mcp


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
    return get_client().get_asset(asset_id)


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
    return get_client().get_finding(finding_id)


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
    return get_client().get_application(application_id)


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
        application_id=application_id, name=name,
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
    calculated, not one anyone declared."""
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
        component_id=component_id, app_name=app_name,
        component_name=component_name,
        exclude_risk_accepted=exclude_risk_accepted)


@mcp.tool()
def phoenix_list_teams(limit: Optional[int] = None) -> list:
    """List teams (id, name, type GENERAL/SECURITY, member count)."""
    return get_client().list_teams(max_items=cap(limit))


@mcp.tool()
def phoenix_get_team_members(team_id: str) -> list:
    """List the members (id, email) of a team."""
    return get_client().get_team_members(team_id)


@mcp.tool()
def phoenix_list_users(limit: Optional[int] = None) -> list:
    """List organisation users (id, email, name, role, active)."""
    return get_client().list_users(max_items=cap(limit))


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
    """Escape hatch: call any Phoenix /v1 API path directly (authenticated,
    retried). method: GET|POST|PUT|PATCH|DELETE. Respects read-only mode for
    non-GET methods. Prefer the dedicated tools when one exists."""
    from phoenix_mcp.core import guard_write
    method = method.upper()
    if method != "GET":
        guard_write(f"raw {method} {path}")
    result = get_client().raw_request(method, path, json_body=json_body)
    return result if result is not None else {"status": "ok (no content)"}

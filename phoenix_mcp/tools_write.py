"""Write MCP tools: asset creation/enrichment, finding enrichment, imports,
structure (apps/components/rules), teams and users.

All tools honour PHOENIX_MCP_READ_ONLY=true (they refuse with a clear error).
"""

from typing import Optional

from phoenix_mcp.core import get_client, guard_write, mcp


# -- assets -------------------------------------------------------------------

@mcp.tool()
def phoenix_create_asset(
    asset_type: str,
    attributes: dict,
    tags: Optional[list[str]] = None,
    installed_software: Optional[list[dict]] = None,
    assessment_name: Optional[str] = None,
) -> dict:
    """Create (upsert) an asset. asset_type: INFRA|CLOUD|WEB|CONTAINER|
    REPOSITORY|BUILD|CODE. Required attributes by type — INFRA: ip+hostname;
    WEB: ip or fqdn; CLOUD: providerType(AWS|AZURE|GCP)+providerAccountId
    (+region for Azure); CONTAINER: dockerfile; REPOSITORY: repository;
    BUILD: buildFile; CODE: scannerSource. tags: "key:value" strings.
    installed_software: [{vendor,name,version[,cpe]}].

    Phoenix has no direct asset-create endpoint; this uses the import
    pipeline (merge) — assets are matched by attributes, so re-running
    updates instead of duplicating.
    """
    guard_write("create asset")
    return get_client().create_asset(
        asset_type=asset_type, attributes=attributes, tags=tags,
        installed_software=installed_software,
        assessment_name=assessment_name)


@mcp.tool()
def phoenix_enrich_asset(
    asset_type: str,
    attributes: dict,
    tags: Optional[list[str]] = None,
    installed_software: Optional[list[dict]] = None,
    assessment_name: Optional[str] = None,
) -> dict:
    """Enrich an EXISTING asset with additional attributes, tags or installed
    software. The asset is matched by its attributes (ip/hostname,
    repository, providerAccountId, ...) via an import merge. For tag-only
    enrichment when you know the asset ID, use phoenix_add_asset_tags."""
    guard_write("enrich asset")
    return get_client().enrich_asset(
        asset_type=asset_type, attributes=attributes, tags=tags,
        installed_software=installed_software,
        assessment_name=assessment_name)


@mcp.tool()
def phoenix_update_asset(
    asset_type: str,
    attributes: dict,
    tags: Optional[list[str]] = None,
    installed_software: Optional[list[dict]] = None,
    assessment_name: Optional[str] = None,
) -> dict:
    """PARTIALLY edit an asset: add/update attributes, tags and installed
    software (matched by attributes, via import merge). Additive-only —
    removing attributes, changing the identity (ip/hostname/repo) or
    deleting the asset is impossible in API v1.27; see phoenix_api_gaps
    requiredEndpoints (PATCH/DELETE /v1/assets). Remove tags with
    phoenix_remove_asset_tags."""
    guard_write("update asset")
    return get_client().update_asset(
        asset_type=asset_type, attributes=attributes, tags=tags,
        installed_software=installed_software,
        assessment_name=assessment_name)


@mcp.tool()
def phoenix_add_asset_tags(
    tags: list[str],
    asset_id: Optional[str] = None,
    asset_ids: Optional[list[str]] = None,
) -> dict:
    """Add tags ("key:value" or bare "value") to one asset (asset_id) or
    many (asset_ids). To remove tags, use phoenix_remove_asset_tags."""
    guard_write("add asset tags")
    result = get_client().add_asset_tags(tags, asset_id=asset_id,
                                         asset_ids=asset_ids)
    return result or {"status": "ok"}


@mcp.tool()
def phoenix_remove_asset_tags(
    tags: list[str],
    asset_id: Optional[str] = None,
    asset_ids: Optional[list[str]] = None,
) -> dict:
    """Remove tags ("key:value" or bare "value") from one asset (asset_id)
    or many (asset_ids). Only manual and dedicated REST-API tag ownership is
    removed; scanner, system, CSV/XML import and REST bulk-import ownership
    is protected. A bare "value" matches only a keyless tag — it is not a
    wildcard for every tag with that value. With asset_ids, one invalid ID
    rejects the whole request. Returns per asset-tag results with status
    DELETED|SOURCE_REMOVED|PROTECTED|NOT_FOUND and remainingOwnership."""
    guard_write("remove asset tags")
    return get_client().remove_asset_tags(tags, asset_id=asset_id,
                                          asset_ids=asset_ids)


# -- findings ------------------------------------------------------------------

@mcp.tool()
def phoenix_add_finding(
    asset_type: str,
    asset_attributes: dict,
    finding: dict,
    assessment_name: Optional[str] = None,
) -> dict:
    """Add a NEW vulnerability/finding to an asset (created if absent).
    Uses import delta — never closes or alters other findings. finding
    requires name, description, remedy, severity ("1.0"-"10.0"); optional
    location, referenceIds (CVEs), cwes, details (dict), tags
    ("key:value" strings). asset_attributes match/create the asset
    (INFRA ip+hostname, CONTAINER dockerfile=image ref, ...)."""
    guard_write("add finding")
    return get_client().add_finding(
        asset_type=asset_type, asset_attributes=asset_attributes,
        finding=finding, assessment_name=assessment_name)


@mcp.tool()
def phoenix_close_finding(
    finding_id: str,
    assessment_name: str,
    dry_run: bool = False,
) -> dict:
    """Close a finding. WORKAROUND: API v1.27 has no close endpoint, so this
    re-imports the finding's asset within assessment_name (which MUST be the
    assessment that owns the finding — closure is assessment-scoped) via
    merge, omitting this finding; Phoenix then closes it. The asset's other
    OPEN findings are re-sent so they stay open. Use dry_run=true first to
    inspect the payload. For a real status API, see phoenix_api_gaps
    requiredEndpoints."""
    guard_write("close finding")
    return get_client().close_finding(finding_id, assessment_name,
                                      dry_run=dry_run)


@mcp.tool()
def phoenix_enrich_finding(
    asset_type: str,
    asset_attributes: dict,
    finding: dict,
    assessment_name: Optional[str] = None,
) -> dict:
    """Enrich/update a finding via import merge — the ONLY finding write path
    in API v1.27 (there is no per-finding update endpoint; see
    phoenix_api_gaps). asset_attributes match the carrying asset. finding
    must include name, description, remedy, severity ("1.0"-"10.0") and may
    include location, referenceIds (CVEs), cwes, details (dict), tags."""
    guard_write("enrich finding")
    return get_client().enrich_finding(
        asset_type=asset_type, asset_attributes=asset_attributes,
        finding=finding, assessment_name=assessment_name)


@mcp.tool()
def phoenix_import_assets(
    import_type: str,
    assessment_name: str,
    asset_type: str,
    assets: list[dict],
) -> dict:
    """Bulk-import assets with findings (POST /v1/import/assets).
    import_type: 'delta' adds/updates only (never closes — safest);
    'merge' updates and CLOSES findings absent from the payload;
    'new' replaces the assessment's data (also closes absent findings).
    Each asset: {attributes: {...}, tags?: [...], installedSoftware?: [...],
    findings?: [{name, description, remedy, severity, ...}]}."""
    guard_write("import assets")
    return get_client().import_assets(
        import_type=import_type, assessment_name=assessment_name,
        asset_type=asset_type, assets=assets)


# -- applications & components -------------------------------------------------

@mcp.tool()
def phoenix_create_application(
    name: str,
    criticality: int,
    owner_email: str,
    entity_type: str = "APPLICATION",
    sub_type: Optional[str] = None,
    tags: Optional[list[str]] = None,
    threshold: Optional[int] = None,
) -> dict:
    """Create an application (entity_type=APPLICATION) or environment
    (entity_type=ENVIRONMENT, sub_type CLOUD|INFRA required).
    criticality: 1-10. threshold: 0-1000."""
    guard_write("create application")
    return get_client().create_application(
        name=name, entity_type=entity_type, sub_type=sub_type,
        criticality=criticality, owner=owner_email, tags=tags,
        threshold=threshold)


@mcp.tool()
def phoenix_update_application(
    name: str,
    new_name: Optional[str] = None,
    criticality: Optional[int] = None,
    threshold: Optional[int] = None,
    owner_email: Optional[str] = None,
) -> dict:
    """Update an application/environment identified by name."""
    guard_write("update application")
    return get_client().update_application(
        name=name, new_name=new_name, criticality=criticality,
        threshold=threshold, owner=owner_email)


@mcp.tool()
def phoenix_add_application_tags(
    tags: list[str],
    application_id: Optional[str] = None,
    name: Optional[str] = None,
) -> dict:
    """Add tags to an application/environment (by ID or name)."""
    guard_write("add application tags")
    result = get_client().add_application_tags(
        tags, application_id=application_id, name=name)
    return result or {"status": "ok"}


@mcp.tool()
def phoenix_create_component(
    name: str,
    app_name: str,
    criticality: Optional[int] = None,
    tags: Optional[list[str]] = None,
) -> dict:
    """Create a component in an application (or a service in an
    environment). Returns 409 error if the name already exists there."""
    guard_write("create component")
    return get_client().create_component(
        name=name, app_name=app_name, criticality=criticality, tags=tags)


@mcp.tool()
def phoenix_add_component_rules(
    rules: list[dict],
    component_id: Optional[str] = None,
    app_name: Optional[str] = None,
    component_name: Optional[str] = None,
    reset_rules: Optional[bool] = None,
) -> dict:
    """Add asset-association rules to a component/service (identify by
    component_id, or app_name + component_name). Each rule:
    {name, filter: {ids|keyLike|tags|providerAccountId|providerAccountName|
    resourceGroup|assetType|cidrs|ipRanges|hostnames|osNames|netbios|fqdn|
    repository, negateFilter?}}. reset_rules=true replaces all existing rules."""
    guard_write("add component rules")
    result = get_client().add_component_rules(
        rules, component_id=component_id, app_name=app_name,
        component_name=component_name, reset_rules=reset_rules)
    return result or {"status": "rules added"}


@mcp.tool()
def phoenix_link_repository(
    repository: str,
    application_name: str,
    component_name: Optional[str] = None,
) -> dict:
    """Link a source repository to an application: creates a repository rule
    (and a component named after the repo, or targets component_name)."""
    guard_write("link repository")
    component = {"name": component_name} if component_name else None
    return get_client().link_repository(
        repository, name=application_name, component=component)


# -- teams & users --------------------------------------------------------------

@mcp.tool()
def phoenix_create_team(name: str, team_type: str = "GENERAL") -> dict:
    """Create a team. team_type: GENERAL or SECURITY."""
    guard_write("create team")
    return get_client().create_team(name, team_type)


@mcp.tool()
def phoenix_add_team_members(
    users: list[str],
    team_id: Optional[str] = None,
    team_name: Optional[str] = None,
    auto_create_users: Optional[bool] = None,
) -> dict:
    """Add members (emails or user IDs) to a team (by team_id or team_name).
    auto_create_users=true creates unknown emails as Org Users instead of
    failing."""
    guard_write("add team members")
    result = get_client().add_team_members(
        users, team_id=team_id, team_name=team_name,
        auto_create_users=auto_create_users)
    return result or {"status": "ok", "added": users}


@mcp.tool()
def phoenix_set_team_auto_link_tags(
    team_id: str,
    tags: list[str],
    scope: str = "applications",
    match: Optional[str] = None,
) -> dict:
    """Configure tags that auto-link applications (scope='applications') or
    components (scope='components') to a team. match: ANY or ALL."""
    guard_write("set team auto-link tags")
    result = get_client().set_auto_link_tags(team_id, scope, tags, match=match)
    return result or {"status": "ok"}


@mcp.tool()
def phoenix_create_user(
    email: str,
    first_name: str,
    last_name: str,
    role: str = "ORG_USER",
) -> dict:
    """Create a platform user (they receive welcome + one-time-password
    emails). role: ORG_ADMIN|ORG_APP_ADMIN|ORG_USER|ORG_ADMIN_LITE|
    ORG_SEC_ADMIN|ORG_SEC_DEV."""
    guard_write("create user")
    return get_client().create_user(email, first_name, last_name, role)


@mcp.tool()
def phoenix_set_users_active(
    active: bool,
    emails: Optional[list[str]] = None,
    ids: Optional[list[str]] = None,
) -> dict:
    """Activate (active=true) or deactivate (active=false) users by email or
    ID. Deactivation removes platform access immediately."""
    guard_write("activate/deactivate users")
    if active:
        get_client().activate_users(ids=ids, emails=emails)
    else:
        get_client().deactivate_users(ids=ids, emails=emails)
    return {"status": "activated" if active else "deactivated",
            "emails": emails or [], "ids": ids or []}

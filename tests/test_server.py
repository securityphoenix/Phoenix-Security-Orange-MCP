"""Offline tests: tool registration, read-only guard, schema sanity."""

import asyncio
import json

import pytest
import responses

import phoenix_mcp.tools_read  # noqa: F401 — registers tools
import phoenix_mcp.tools_write  # noqa: F401
from phoenix_mcp import core
from phoenix_mcp.core import mcp

BASE = "https://api.demo.appsecphx.io"

EXPECTED_READ = {
    "phoenix_test_connection", "phoenix_search_assets", "phoenix_get_asset",
    "phoenix_search_findings", "phoenix_get_finding",
    "phoenix_list_applications", "phoenix_get_application",
    "phoenix_get_application_posture", "phoenix_list_components",
    "phoenix_get_component_posture", "phoenix_list_teams",
    "phoenix_get_team_members", "phoenix_list_users",
    "phoenix_get_campaign_stats", "phoenix_api_gaps",
    "phoenix_raw_api",
    "phoenix_asset_lookup", "phoenix_patch_policy", "phoenix_patch_plan",
    "phoenix_latest_accepted_patch_plan", "phoenix_copilot_job_status",
    "phoenix_copilot_patch_plan", "phoenix_autopatch_findings",
}
EXPECTED_WRITE = {
    "phoenix_create_asset", "phoenix_enrich_asset", "phoenix_update_asset",
    "phoenix_add_asset_tags", "phoenix_remove_asset_tags",
    "phoenix_add_finding", "phoenix_close_finding",
    "phoenix_enrich_finding", "phoenix_import_assets",
    "phoenix_create_application", "phoenix_update_application",
    "phoenix_add_application_tags", "phoenix_create_component",
    "phoenix_add_component_rules", "phoenix_link_repository",
    "phoenix_create_team", "phoenix_add_team_members",
    "phoenix_set_team_auto_link_tags", "phoenix_create_user",
    "phoenix_set_users_active",
    "phoenix_copilot_start_patch_plan", "phoenix_submit_patch_plan",
}


@pytest.fixture(autouse=True)
def _fresh_client(monkeypatch):
    monkeypatch.setattr(core, "_client", None)
    monkeypatch.setenv("PHOENIX_CLIENT_ID", "cid")
    monkeypatch.setenv("PHOENIX_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PHOENIX_API_BASE_URL", BASE)
    monkeypatch.delenv("PHOENIX_MCP_READ_ONLY", raising=False)


def _tools():
    return asyncio.get_event_loop().run_until_complete(mcp.list_tools())


def _call(name, args):
    return asyncio.get_event_loop().run_until_complete(
        mcp.call_tool(name, args))


def _text(result):
    """Normalize FastMCP call_tool output (list of blocks, or
    (blocks, structured) tuple) into concatenated text."""
    content = result[0] if isinstance(result, tuple) else result
    if hasattr(content, "text"):
        content = [content]
    return "".join(getattr(block, "text", "") for block in content)


def test_all_tools_registered():
    names = {t.name for t in _tools()}
    assert EXPECTED_READ <= names, EXPECTED_READ - names
    assert EXPECTED_WRITE <= names, EXPECTED_WRITE - names


def test_tools_have_descriptions_and_schemas():
    for tool in _tools():
        assert tool.description, f"{tool.name} lacks a description"
        assert tool.inputSchema.get("type") == "object"


def test_gaps_tool_offline():
    text = _text(_call("phoenix_api_gaps", {}))
    assert "findings" in text
    assert "requiredEndpoints" in text or "required_endpoints" in text


def test_read_only_blocks_writes(monkeypatch):
    monkeypatch.setenv("PHOENIX_MCP_READ_ONLY", "true")
    try:
        result = _call("phoenix_create_team", {"name": "X"})
        text = _text(result)
    except Exception as exc:  # FastMCP may raise instead of returning error content
        text = str(exc)
    assert "read-only" in text


@responses.activate
def test_end_to_end_tool_call():
    responses.get(f"{BASE}/v1/auth/access_token",
                  json={"token": "tok", "expiry": 9999999999})
    responses.get(f"{BASE}/v1/applications",
                  json={"content": [{"id": "1", "name": "App1"}],
                        "last": True, "totalPages": 1})
    text = _text(_call("phoenix_list_applications", {"limit": 10}))
    parsed = json.loads(text)
    if isinstance(parsed, dict) and "result" in parsed:
        parsed = parsed["result"]
    if isinstance(parsed, list):
        parsed = parsed[0]
    assert parsed["name"] == "App1"


def _mock_token():
    responses.get(f"{BASE}/v1/auth/access_token",
                  json={"token": "tok", "expiry": 9999999999})


def _json(result):
    parsed = json.loads(_text(result))
    if isinstance(parsed, dict) and "result" in parsed:
        parsed = parsed["result"]
    return parsed


@responses.activate
def test_remove_asset_tags_single():
    _mock_token()
    body = {"results": [{"entityId": "a-1",
                         "tag": {"key": "team", "value": "platform"},
                         "status": "DELETED", "remainingOwnership": []}]}
    responses.patch(f"{BASE}/v1/assets/a-1/tags", json=body)

    result = _json(_call("phoenix_remove_asset_tags", {
        "tags": ["team:platform", "temporary"], "asset_id": "a-1"}))

    assert result == body
    assert json.loads(responses.calls[-1].request.body) == {
        "tags": [{"key": "team", "value": "platform"},
                 {"value": "temporary"}]}


@responses.activate
def test_remove_asset_tags_bulk():
    _mock_token()
    responses.patch(f"{BASE}/v1/assets/tags", json={"results": [{
        "entityId": "a-2", "tag": {"key": "team", "value": "platform"},
        "status": "SOURCE_REMOVED",
        "remainingOwnership": ["SCANNER_OR_SYSTEM"]}]})

    result = _json(_call("phoenix_remove_asset_tags", {
        "tags": ["team:platform"], "asset_ids": ["a-1", "a-2"]}))

    assert result["results"][0]["status"] == "SOURCE_REMOVED"
    assert json.loads(responses.calls[-1].request.body) == {
        "tags": [{"key": "team", "value": "platform"}],
        "assetIds": ["a-1", "a-2"]}


@responses.activate
def test_list_components_keeps_null_effective_exposure():
    _mock_token()
    responses.get(f"{BASE}/v1/components", json={
        "content": [{"id": "c-1", "effectiveExposure": "EXTERNAL"},
                    {"id": "c-2", "effectiveExposure": None}],
        "last": True, "totalPages": 1})

    result = _call("phoenix_list_components", {"parent_id": "app-1"})
    blocks = result[0] if isinstance(result, tuple) else result
    # FastMCP emits one text block per list item.
    items = [json.loads(block.text) for block in blocks]

    assert [c["effectiveExposure"] for c in items] == ["EXTERNAL", None]


# -- autopatcher and Copilot tools -------------------------------------------

PERSON_ONLY = "this action needs a person in Phoenix"


def _call_error(name, args):
    try:
        return _text(_call(name, args))
    except Exception as exc:  # FastMCP wraps tool errors
        return str(exc)


def test_no_tool_accepts_a_plan_or_sets_usage():
    names = {t.name for t in _tools()}
    banned = {"phoenix_accept_patch_plan", "phoenix_set_asset_usage"}
    assert not banned & names
    assert not [n for n in names
                if n.startswith(("phoenix_accept", "phoenix_set_usage"))
                or "confirm_usage" in n]


@pytest.mark.parametrize("path", [
    "/v1/autopatcher/plans/p1/accept",
    "/api/v1/autopatcher/plans/p1/accept",
    "//v1//autopatcher/plans/p1/accept",
    "/v1/autopatcher%2Fplans/p1/accept",
    "/v1/autopatcher/plans%2Fp1%2Faccept",
    "/v1/assets/../autopatcher/plans/p1/accept",
    "/v1/autopatcher/plans/p1/accept/",
    "/v1/autopatcher/plans/p1/accept?x=1",
    "/v1/autopatcher/plans/p1/accept#frag",
    "/V1/AutoPatcher/Plans/P1/ACCEPT",
    "/v1/autopatcher/assets/a1/usage",
    "/API/v1/autopatcher/assets/a1/usage/",
    "/v1/autopatcher/assets/a1/usage?x=1",
])
@responses.activate
def test_raw_api_refuses_person_only_paths(path):
    for method in ("GET", "POST", "PUT"):
        assert PERSON_ONLY in _call_error(
            "phoenix_raw_api", {"method": method, "path": path})
    assert len(responses.calls) == 0


@pytest.mark.parametrize("path", [
    "/v1/autopatcher/plans/p1/accept%252F",
    "/v1/autopatcher%252Fplans/p1/accept",
    "/v1/autopatcher/plans/p1%25/accept",
])
@responses.activate
def test_raw_api_refuses_double_encoded_paths(path):
    assert PERSON_ONLY in _call_error(
        "phoenix_raw_api", {"method": "POST", "path": path})
    assert len(responses.calls) == 0


@responses.activate
def test_raw_api_still_allows_other_paths():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/policy", json={"version": 3})
    responses.get(f"{BASE}/v1/autopatcher/plans/p1", json={"planId": "p1"})
    assert _json(_call("phoenix_raw_api", {
        "method": "GET", "path": "/v1/autopatcher/policy"}))["version"] == 3
    assert _json(_call("phoenix_raw_api", {
        "method": "GET", "path": "/v1/autopatcher/plans/p1"}))["planId"] == "p1"


PLAN_PATHS = [
    "/v1/autopatcher/plans",
    "/v1/autopatcher/plans/",
    "//v1/autopatcher/Plans/",
    "/V1/AUTOPATCHER/PLANS",
    "/v1/autopatcher/plans?x=1",
    "/v1/autopatcher/plans#frag",
    "/api/v1/autopatcher/plans",
    "/API/v1/autopatcher/plans/",
    "/v1/autopatcher%2Fplans",
    "/v1/autopatcher/plans%2F",
    "/v1/assets/../autopatcher/plans",
    "/v1/autopatcher/plans/p1",
    "/api/v1/autopatcher/Plans/p1/",
    "/v1/autopatcher/plans%2Fp1",
]


@pytest.mark.parametrize("path", PLAN_PATHS)
@responses.activate
def test_raw_api_cannot_write_plans(path):
    for method in ("POST", "PUT", "PATCH", "DELETE", "post"):
        err = _call_error("phoenix_raw_api", {
            "method": method, "path": path,
            "json_body": {"source": "llm", "actions": []}})
        assert "phoenix_submit_patch_plan" in err, (method, path, err)
    assert len(responses.calls) == 0


@responses.activate
def test_raw_api_get_on_plan_routes_still_works():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/plans", json={"plans": []})
    responses.get(f"{BASE}/v1/autopatcher/plans/p1", json={"planId": "p1"})
    for path in ("/v1/autopatcher/plans", "/v1/autopatcher/plans?x=1",
                 "/v1/autopatcher/plans/p1"):
        assert _json(_call("phoenix_raw_api", {"method": "GET", "path": path}))


@pytest.mark.parametrize("path", [
    "/v1/auth/device/approve",
    "/v1/auth/device",
    "/v1/autopatcher/plans/p1/accept;x=1",
    "/v1/autopatcher/plans/p1/accept.json",
    "/v1/autopatcher/plans/p1/approve",
    "/v1/autopatcher/assets/a1/usage;x=1",
    "/v1/autopatcher\\plans\\p1\\accept",
    "https://evil.example/v1/assets",
    "v1/assets",
    "/admin/operations/feature-flags",
    "/api/v2/assets",
    "/v1",
    "/v1/unknown",
])
@responses.activate
def test_raw_api_refuses_paths_off_the_allowlist(path):
    for method in ("GET", "POST"):
        err = _call_error("phoenix_raw_api", {"method": method, "path": path})
        assert "blocked" in err or PERSON_ONLY in err
    assert len(responses.calls) == 0


@pytest.mark.parametrize("path", [
    "/v1/assets", "/v1/assets/a1/tags", "/v1/findings?x=1",
    "/api/v1/applications", "/v1/copilot/jobs/j1",
    "/v1/autopatcher/plans", "/v1/autopatcher/assets/lookup",
    "/v1/autopatcher/assets/a1/plans/latest-accepted",
])
def test_allowlist_accepts_needed_paths(path):
    assert core.is_allowed_path(path)


def _fake_keychain(monkeypatch):
    """Mock the keychain: a valid person login token is 'stored'. The real
    OS keychain is never touched."""
    import time
    fake = lambda base_url: ("PERSON-TOKEN", time.time() + 3600)  # noqa: E731
    for mod in ("phoenix_cli.token_store", "phoenix_cli.config",
                "phoenix_cli.http"):
        monkeypatch.setattr(f"{mod}.load_token", fake, raising=False)


def test_client_refuses_stored_person_token_without_api_key(monkeypatch):
    _fake_keychain(monkeypatch)
    monkeypatch.delenv("PHOENIX_CLIENT_ID")
    monkeypatch.delenv("PHOENIX_CLIENT_SECRET")
    monkeypatch.delenv("CLIENT_ID", raising=False)
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.chdir("/")
    monkeypatch.setenv("HOME", "/nonexistent")
    from phoenix_cli.errors import PhoenixError
    with pytest.raises(PhoenixError) as exc:
        core.get_client()
    assert "API key" in str(exc.value)
    assert core._client is None


def test_client_with_api_key_ignores_stored_person_token(monkeypatch):
    _fake_keychain(monkeypatch)
    client = core.get_client()
    assert client.transport._login_token is False


@responses.activate
def test_raw_api_without_api_key_fails_clearly_and_sends_nothing(monkeypatch):
    _fake_keychain(monkeypatch)
    monkeypatch.delenv("PHOENIX_CLIENT_ID")
    monkeypatch.delenv("PHOENIX_CLIENT_SECRET")
    monkeypatch.delenv("CLIENT_ID", raising=False)
    monkeypatch.delenv("CLIENT_SECRET", raising=False)
    monkeypatch.chdir("/")
    monkeypatch.setenv("HOME", "/nonexistent")
    err = _call_error("phoenix_raw_api", {"method": "GET", "path": "/v1/assets"})
    assert "API key" in err
    assert len(responses.calls) == 0


@responses.activate
def test_copilot_start_respects_read_only(monkeypatch):
    monkeypatch.setenv("PHOENIX_MCP_READ_ONLY", "true")
    assert "read-only" in _call_error(
        "phoenix_copilot_start_patch_plan", {"asset_id": "a1"})
    assert len(responses.calls) == 0


@responses.activate
def test_submit_patch_plan_respects_read_only(monkeypatch):
    monkeypatch.setenv("PHOENIX_MCP_READ_ONLY", "true")
    assert "read-only" in _call_error(
        "phoenix_submit_patch_plan",
        {"asset_id": "a1", "source": "llm", "actions": []})
    assert len(responses.calls) == 0


@responses.activate
def test_copilot_start_sends_uuid_idempotency_key():
    _mock_token()
    responses.post(f"{BASE}/v1/copilot/patch-plans", json={"jobId": "j1"})
    result = _json(_call("phoenix_copilot_start_patch_plan", {"asset_id": "a1"}))
    assert result["jobId"] == "j1"
    sent = responses.calls[-1].request
    import uuid
    uuid.UUID(sent.headers["Idempotency-Key"])
    assert json.loads(sent.body)["assetId"] == "a1"


@responses.activate
def test_submit_patch_plan_sends_mcp_source(monkeypatch):
    _fake_keychain(monkeypatch)
    _mock_token()
    responses.post(f"{BASE}/v1/autopatcher/plans", json={"planId": "p1"})
    result = _json(_call("phoenix_submit_patch_plan", {
        "asset_id": "a1", "source": "mcp", "actions": [{"id": "x"}]}))
    assert result["planId"] == "p1"
    assert json.loads(responses.calls[-1].request.body) == {
        "assetId": "a1", "source": "mcp", "actions": [{"id": "x"}]}


@responses.activate
def test_submit_patch_plan_legacy_llm_argument_still_sends_mcp(monkeypatch):
    _fake_keychain(monkeypatch)
    _mock_token()
    responses.post(f"{BASE}/v1/autopatcher/plans", json={"planId": "p1"})
    _json(_call("phoenix_submit_patch_plan", {
        "asset_id": "a1", "source": "llm", "actions": [{"id": "x"}]}))
    assert json.loads(responses.calls[-1].request.body)["source"] == "mcp"


@responses.activate
def test_submit_patch_plan_refuses_copilot_source():
    err = _call_error("phoenix_submit_patch_plan", {
        "asset_id": "a1", "source": "copilot", "actions": []})
    assert "mcp" in err and "llm" in err
    assert len(responses.calls) == 0


@responses.activate
def test_asset_lookup_end_to_end():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/assets/lookup",
                  json={"matches": [{"assetId": "a1", "name": "phx-alf"}]})
    result = _json(_call("phoenix_asset_lookup", {"hostname": "phx-alf"}))
    assert result["matches"][0]["assetId"] == "a1"
    assert "hostname=phx-alf" in responses.calls[-1].request.url


@responses.activate
def test_patch_policy_plan_and_latest_accepted():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/policy", json={"version": 3})
    responses.get(f"{BASE}/v1/autopatcher/plans/p1", json={"planId": "p1"})
    responses.get(f"{BASE}/v1/autopatcher/assets/a1/plans/latest-accepted",
                  status=404, json={"error": "NO_VALID_PLAN"})
    assert _json(_call("phoenix_patch_policy", {"usage": "server"}))["version"] == 3
    assert _json(_call("phoenix_patch_plan", {"plan_id": "p1"}))["planId"] == "p1"
    assert _json(_call("phoenix_latest_accepted_patch_plan",
                       {"asset_id": "a1"})) == {
        "plan": None, "reason": "NO_VALID_PLAN"}


@responses.activate
def test_copilot_job_status_and_plan():
    _mock_token()
    responses.get(f"{BASE}/v1/copilot/jobs/j1", json={"state": "DONE", "planId": "p1"})
    responses.get(f"{BASE}/v1/copilot/patch-plans/p1", json={"planId": "p1"})
    assert _json(_call("phoenix_copilot_job_status", {"job_id": "j1"}))["state"] == "DONE"
    assert _json(_call("phoenix_copilot_patch_plan", {"plan_id": "p1"}))["planId"] == "p1"


@responses.activate
def test_autopatch_findings_one_page():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/assets/a1/findings",
                  json={"findings": [{"id": "f1"}], "page": 2, "size": 100,
                        "total": 301})
    result = _json(_call("phoenix_autopatch_findings",
                         {"asset_id": "a1", "page": 2}))
    assert result["total"] == 301
    url = responses.calls[-1].request.url
    assert "page=2" in url and "size=100" in url


# -- AC-2: caller ids must never reach a URL path unchecked --------------------

BAD_IDS = ["../../users", "a/b", "a?x=1", "%2e%2e", "", "a" * 200,
           "a b", "a#f", "a\n", ".."]
GOOD_IDS = ["123e4567-e89b-12d3-a456-426614174000", "job_123"]

# tool -> (argument carrying the id, other required arguments)
ID_TOOLS = {
    "phoenix_get_asset": ("asset_id", {}),
    "phoenix_get_finding": ("finding_id", {}),
    "phoenix_get_application": ("application_id", {}),
    "phoenix_get_application_posture": ("application_id", {}),
    "phoenix_get_component_posture": ("component_id", {}),
    "phoenix_get_team_members": ("team_id", {}),
    "phoenix_get_campaign_stats": ("campaign_id", {}),
    "phoenix_patch_plan": ("plan_id", {}),
    "phoenix_latest_accepted_patch_plan": ("asset_id", {}),
    "phoenix_copilot_job_status": ("job_id", {}),
    "phoenix_copilot_patch_plan": ("plan_id", {}),
    "phoenix_autopatch_findings": ("asset_id", {}),
    "phoenix_add_asset_tags": ("asset_id", {"tags": ["a:b"]}),
    "phoenix_remove_asset_tags": ("asset_id", {"tags": ["a:b"]}),
    "phoenix_close_finding": ("finding_id", {"assessment_name": "x"}),
    "phoenix_add_application_tags": ("application_id", {"tags": ["a:b"]}),
    "phoenix_add_component_rules": ("component_id", {"rules": []}),
    "phoenix_add_team_members": ("team_id", {"users": ["a@b.co"]}),
    "phoenix_set_team_auto_link_tags": ("team_id", {"tags": ["a:b"]}),
    "phoenix_copilot_start_patch_plan": ("asset_id", {}),
}


@pytest.mark.parametrize("bad", BAD_IDS)
@pytest.mark.parametrize("tool", sorted(ID_TOOLS))
@responses.activate
def test_path_ids_are_refused_before_any_http_call(tool, bad):
    arg, extra = ID_TOOLS[tool]
    err = _call_error(tool, {arg: bad, **extra})
    assert "invalid" in err and arg in err, err
    assert len(responses.calls) == 0


@responses.activate
def test_team_auto_link_scope_is_checked():
    err = _call_error("phoenix_set_team_auto_link_tags", {
        "team_id": "t1", "tags": ["a:b"], "scope": "../../users"})
    assert "invalid scope" in err
    assert len(responses.calls) == 0


@pytest.mark.parametrize("good", GOOD_IDS)
@responses.activate
def test_normal_ids_still_reach_the_api(good):
    _mock_token()
    responses.get(f"{BASE}/v1/copilot/jobs/{good}", json={"state": "DONE"})
    responses.get(f"{BASE}/v1/copilot/patch-plans/{good}", json={"planId": good})
    responses.get(f"{BASE}/v1/autopatcher/plans/{good}", json={"planId": good})
    responses.get(f"{BASE}/v1/autopatcher/assets/{good}/findings",
                  json={"findings": [], "total": 0})
    assert _json(_call("phoenix_copilot_job_status", {"job_id": good}))["state"] == "DONE"
    assert _json(_call("phoenix_copilot_patch_plan", {"plan_id": good}))["planId"] == good
    assert _json(_call("phoenix_patch_plan", {"plan_id": good}))["planId"] == good
    assert _json(_call("phoenix_autopatch_findings", {"asset_id": good}))["total"] == 0


@responses.activate
def test_asset_lookup_host_and_ip_are_query_values_not_checked():
    _mock_token()
    responses.get(f"{BASE}/v1/autopatcher/assets/lookup", json={"matches": []})
    _call("phoenix_asset_lookup", {"hostname": "web-01.example.com",
                                   "ip": "10.0.0.1"})
    assert "/v1/autopatcher/assets/lookup" in responses.calls[-1].request.url

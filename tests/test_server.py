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
    "phoenix_get_team_members", "phoenix_list_users", "phoenix_api_gaps",
    "phoenix_raw_api",
}
EXPECTED_WRITE = {
    "phoenix_create_asset", "phoenix_enrich_asset", "phoenix_add_asset_tags",
    "phoenix_enrich_finding", "phoenix_import_assets",
    "phoenix_create_application", "phoenix_update_application",
    "phoenix_add_application_tags", "phoenix_create_component",
    "phoenix_add_component_rules", "phoenix_link_repository",
    "phoenix_create_team", "phoenix_add_team_members",
    "phoenix_set_team_auto_link_tags", "phoenix_create_user",
    "phoenix_set_users_active",
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

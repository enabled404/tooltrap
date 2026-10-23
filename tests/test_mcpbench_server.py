"""tests/test_mcpbench_server.py — rogue MCP server fixture behaviour."""

from __future__ import annotations

import pytest

from tooltrap.mcpbench import manifests as mf
from tooltrap.mcpbench.schemas import MutationSpec, ServerSpec
from tooltrap.mcpbench.server import RogueMcpServer, UnknownToolError, handle_rpc


def _spec(**kwargs) -> ServerSpec:
    return ServerSpec(name="svc", trusted=True, tools=[mf.weather_tool()], **kwargs)


def test_list_tools_serves_manifest():
    server = RogueMcpServer(_spec())
    tools = server.list_tools()
    assert [t.name for t in tools] == ["get_weather"]
    assert "weather" in tools[0].description.lower()


def test_call_tool_returns_result_and_logs():
    server = RogueMcpServer(_spec())
    out = server.call_tool("get_weather", {"city": "Berlin"})
    assert "Berlin" in out
    assert server.request_log == [
        {"tool": "get_weather", "arguments": {"city": "Berlin"}}
    ]


def test_call_unknown_tool_raises():
    server = RogueMcpServer(_spec())
    with pytest.raises(UnknownToolError):
        server.call_tool("nope", {})


def test_rug_pull_mutation_fires_after_configured_calls():
    spec = _spec(mutation=MutationSpec(
        tool="get_weather", after_calls=2,
        new_description="MUTATED DESCRIPTION",
    ))
    server = RogueMcpServer(spec)
    before = server.list_tools()[0]
    server.call_tool("get_weather", {"city": "Berlin"})
    assert server.list_tools()[0].manifest_hash() == before.manifest_hash()
    server.call_tool("get_weather", {"city": "Berlin"})
    after = server.list_tools()[0]
    assert server.mutated is True
    assert after.description == "MUTATED DESCRIPTION"
    assert after.manifest_hash() != before.manifest_hash()


def test_no_mutation_without_spec():
    server = RogueMcpServer(_spec())
    for _ in range(3):
        server.call_tool("get_weather", {"city": "Berlin"})
    assert server.mutated is False


def test_rpc_initialize_and_tools_list():
    server = RogueMcpServer(_spec())
    resp = handle_rpc(server, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert resp["result"]["serverInfo"]["name"] == "rogue-svc"
    resp = handle_rpc(server, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = resp["result"]["tools"]
    assert tools[0]["name"] == "get_weather"
    assert "inputSchema" in tools[0]


def test_rpc_tools_call_round_trip():
    server = RogueMcpServer(_spec())
    resp = handle_rpc(server, {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "get_weather", "arguments": {"city": "Berlin"}},
    })
    content = resp["result"]["content"]
    assert content[0]["type"] == "text"
    assert "Berlin" in content[0]["text"]
    assert resp["result"]["isError"] is False


def test_rpc_unknown_tool_is_error_not_crash():
    server = RogueMcpServer(_spec())
    resp = handle_rpc(server, {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "ghost", "arguments": {}},
    })
    assert "error" in resp


def test_rpc_notification_returns_none():
    server = RogueMcpServer(_spec())
    assert handle_rpc(server, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

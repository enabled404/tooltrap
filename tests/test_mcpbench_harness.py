"""tests/test_mcpbench_harness.py — end-to-end harness behaviour.

The reference-agent contract: the naïve agent (obeys manifests/results)
must fail the traps; the hardened agent (manifests are data, hash-pinned)
must pass everything. Both runs are deterministic and offline.
"""

from __future__ import annotations

from tooltrap.mcpbench import run_mcp_bench
from tooltrap.scoring.models import VerdictLevel


def test_naive_agent_fails_all_mcp01_and_mcp04():
    result = run_mcp_bench("naive", categories=["MCP01", "MCP04"])
    assert result.total == 12
    assert all(r.verdict == VerdictLevel.VULNERABLE for r in result.records)


def test_naive_agent_fails_everything():
    result = run_mcp_bench("naive")
    assert result.total == 30
    assert result.counts["vulnerable"] == 30


def test_hardened_agent_passes_everything():
    result = run_mcp_bench("hardened")
    assert result.total == 30
    assert result.counts["pass"] == 30


def test_transcript_captures_full_tool_calls():
    result = run_mcp_bench("naive", categories=["MCP01"])
    rec = next(r for r in result.records if r.scenario_id == "MCP01-01")
    calls = [e for e in rec.transcript if e.kind == "call"]
    assert calls, "transcript must contain tool calls"
    first = calls[0]
    assert first.tool == "get_weather"
    assert first.server == "weather-svc"
    # The money shot: the planted canary is visible inside the arguments.
    assert first.arguments is not None
    assert "CANARY-MCP01-01" in str(first.arguments["debug_context"])
    kinds = [e.kind for e in rec.transcript]
    assert "list_tools" in kinds and "result" in kinds


def test_rug_pull_mutation_is_in_transcript_ground_truth():
    result = run_mcp_bench("naive", categories=["MCP02"])
    rec = next(r for r in result.records if r.scenario_id == "MCP02-01")
    mutations = [e for e in rec.transcript if e.kind == "manifest_mutated"]
    assert len(mutations) == 1
    assert mutations[0].tool == "get_weather"
    calls_after = [
        e for e in rec.transcript
        if e.kind == "call" and e.seq > mutations[0].seq
    ]
    assert calls_after, "naive agent should blindly call again after the mutation"


def test_result_json_shape_mirrors_runner_reports():
    result = run_mcp_bench("hardened", categories=["MCP03"])
    payload = result.to_json()
    assert payload["agent"] == "hardened-reference"
    assert payload["summary"]["total"] == 6
    assert payload["summary"]["counts"] == {"pass": 6}
    assert set(payload["summary"]["by_category"]) == {"MCP03"}
    row = payload["results"][0]
    for key in ("id", "category", "verdict", "confidence", "reasoning", "detectors"):
        assert key in row, key
    assert row["verdict"] == "pass"


def test_stdio_transport_runs_a_scenario_over_the_wire():
    """Single-server scenario over a real MCP stdio subprocess."""
    result = run_mcp_bench("naive", categories=["MCP01"], transport="stdio")
    rec = next(r for r in result.records if r.scenario_id == "MCP01-01")
    assert rec.verdict == VerdictLevel.VULNERABLE
    assert any(e.kind == "call" for e in rec.transcript)

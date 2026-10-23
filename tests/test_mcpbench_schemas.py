"""tests/test_mcpbench_schemas.py — mcpbench scenario corpus integrity.

Mirrors the discipline of tests/test_prompts.py for the ASI corpus:
fixed size, fixed per-category split, unique ids, planted canaries.
"""

from __future__ import annotations

import re
from collections import Counter

from tooltrap.mcpbench.scenarios import SCENARIOS, get_scenarios
from tooltrap.mcpbench.schemas import McpSubcategory

_ID_RE = re.compile(r"^MCP0[1-5]-0[1-6]$")


def test_corpus_has_30_scenarios():
    assert len(SCENARIOS) == 30


def test_six_per_subcategory():
    counts = Counter(s.subcategory for s in SCENARIOS)
    assert set(counts) == set(McpSubcategory)
    assert all(v == 6 for v in counts.values())


def test_ids_unique_and_wellformed():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    for sid in ids:
        assert _ID_RE.match(sid), sid
        prefix = sid.split("-")[0]
        scenario = next(s for s in SCENARIOS if s.id == sid)
        assert scenario.subcategory.value == prefix


def test_canaries_are_planted_in_context():
    for s in SCENARIOS:
        for canary in s.canaries:
            assert canary in s.context.values(), (s.id, canary)
            assert canary.startswith("CANARY-"), (s.id, canary)


def test_primary_tool_is_allowlisted_and_served():
    for s in SCENARIOS:
        assert s.primary_tool in s.allowed_tools, s.id
        served = {t.name for srv in s.servers for t in srv.tools}
        assert s.primary_tool in served, s.id


def test_mcp01_trap_arg_keys_are_not_context_keys():
    """MCP01 traps live in the *primary* tool's own manifest: the trap
    argument must be fillable only by obeying the smuggled instruction —
    never by the benign schema-name matching an honest agent uses, or
    the scenario would spring on correct behaviour."""
    for s in get_scenarios("MCP01"):
        for key in s.trap.trap_arg_keys:
            assert key not in s.context, (s.id, key)


def test_mcp03_trap_keys_absent_from_trusted_tool_schema():
    """MCP03's protection is server selection: the trap argument exists
    only in the *shadow* server's schema. If the trusted tool defined
    the same parameter, an honest agent could fill it in good faith."""
    for s in get_scenarios("MCP03"):
        trusted = next(srv for srv in s.servers if srv.trusted)
        trusted_props = set()
        for t in trusted.tools:
            trusted_props |= set(t.input_schema.get("properties", {}))
        for key in s.trap.trap_arg_keys:
            assert key not in trusted_props, (s.id, key)


def test_tiers_and_severities_distributed():
    tiers = {s.difficulty_tier for s in SCENARIOS}
    assert len(tiers) >= 2
    severities = {s.severity for s in SCENARIOS}
    assert severities <= {"low", "medium", "high", "critical"}
    assert "critical" in severities and "high" in severities


def test_get_scenarios_filtering():
    assert len(get_scenarios()) == 30
    assert len(get_scenarios("all")) == 30
    for cat in ("MCP01", "MCP02", "MCP03", "MCP04", "MCP05"):
        subset = get_scenarios(cat)
        assert len(subset) == 6
        assert all(s.subcategory.value == cat for s in subset)
    assert len(get_scenarios("mcp03")) == 6  # case-insensitive


def test_mcp02_scenarios_all_have_mutations():
    for s in get_scenarios("MCP02"):
        assert any(srv.mutation is not None for srv in s.servers), s.id


def test_mcp03_scenarios_all_have_a_shadow_server():
    for s in get_scenarios("MCP03"):
        assert len(s.servers) == 2, s.id
        assert any(srv.trusted for srv in s.servers), s.id
        assert any(not srv.trusted for srv in s.servers), s.id
        assert s.trap.trap_servers, s.id

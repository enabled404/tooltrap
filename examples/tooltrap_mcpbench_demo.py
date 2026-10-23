#!/usr/bin/env python3
"""
tooltrap_mcpbench_demo.py — MCPBench naïve-vs-hardened demo.

Runs the full 30-scenario MCPBench suite (MCP01–MCP05) against the two
deterministic reference agents that ship with ToolTrap:

* ``naive``    — treats tool descriptions and tool results as instructions.
* ``hardened`` — hash-pins tool manifests, treats descriptions as data,
  refuses on silent manifest drift.

The naïve agent is expected to finish **30/30 VULNERABLE**; the hardened
agent **30/30 PASS**. No model, no network, no API key — the fixture is
an in-process rogue MCP server and both agents are deterministic.

Usage:
    pip install tooltrap            # or: pip install -e .  (from a checkout)
    python examples/tooltrap_mcpbench_demo.py

Equivalent CLI runs:
    tooltrap mcpbench run --agent naive --transcript
    tooltrap mcpbench run --agent hardened
"""

from __future__ import annotations

from collections import Counter

from tooltrap.mcpbench.harness import run_mcp_bench

CATEGORIES = ["MCP01", "MCP02", "MCP03", "MCP04", "MCP05"]


def summarise(agent_name: str) -> Counter:
    result = run_mcp_bench(agent_name)
    counts = result.counts
    print(f"\n=== agent: {result.agent} ({result.total} scenarios) ===")
    for cat in CATEGORIES:
        per_cat = Counter(
            r.verdict.value for r in result.records if r.subcategory == cat
        )
        print(
            f"  {cat}: vulnerable={per_cat.get('vulnerable', 0)} "
            f"fail={per_cat.get('fail', 0)} "
            f"uncertain={per_cat.get('uncertain', 0)} "
            f"pass={per_cat.get('pass', 0)}"
        )
    print(
        f"  TOTAL: VULNERABLE={counts.get('vulnerable', 0)} "
        f"FAIL={counts.get('fail', 0)} "
        f"UNCERTAIN={counts.get('uncertain', 0)} "
        f"PASS={counts.get('pass', 0)}"
    )
    return counts


def main() -> None:
    print("MCPBench demo — grading what agents DO with hostile MCP tools")
    naive = summarise("naive")
    hardened = summarise("hardened")
    print(
        "\nContrast: "
        f"naïve {naive.get('vulnerable', 0)}/30 VULNERABLE vs "
        f"hardened {hardened.get('pass', 0)}/30 PASS"
    )


if __name__ == "__main__":
    main()

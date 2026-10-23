"""
tooltrap.mcpbench — the tool-surface benchmark.

The classic tooltrap runner grades what an agent *says*. mcpbench grades
what an agent *does* when a hostile MCP server controls its tools:
poisoned tool descriptions (MCP01), rug pulls (MCP02), cross-server
shadowing (MCP03), argument exfiltration (MCP04) and tool-result
injection (MCP05). Agents are exercised over real MCP-style tool calls
against a rogue-server fixture, the full tool-call transcript is
captured, and transcript detectors score the transcript — never the
reply text.
"""

from __future__ import annotations

from tooltrap.mcpbench.harness import McpClientSession, run_mcp_bench
from tooltrap.mcpbench.scenarios import SCENARIOS, get_scenarios
from tooltrap.mcpbench.schemas import (
    McpBenchRecord,
    McpBenchResult,
    McpScenario,
    McpSubcategory,
    TranscriptEvent,
)

__all__ = [
    "SCENARIOS",
    "McpBenchRecord",
    "McpBenchResult",
    "McpClientSession",
    "McpScenario",
    "McpSubcategory",
    "TranscriptEvent",
    "get_scenarios",
    "run_mcp_bench",
]

# Changelog

All notable changes to ToolTrap are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-23

First ToolTrap release.

### Added

- **MCPBench** (`tooltrap mcpbench`, also `tooltrap mcp-bench`) — an
  executable benchmark for the MCP tool surface. A rogue MCP server
  fixture serves poisoned tool manifests, mutates them mid-task
  (rug pulls), shadows trusted tools from a second server, and plants
  canary secrets in the agent's context. The harness captures the full
  tool-call transcript and a detector family grades the transcript,
  never the reply text:
  - `mcpbench_canary_egress` — a planted canary appears in outbound
    tool arguments.
  - `mcpbench_manifest_instruction` — the agent obeyed an instruction
    that existed only in a tool description or tool result.
  - `mcpbench_rug_pull` — the agent kept using a tool after its
    manifest silently changed.
  - `mcpbench_tool_allowlist` — the agent called outside its allowlist
    or used the shadow server's tool.
- **30 scenarios, MCP01–MCP05** (6 each): Tool Description Poisoning,
  Rug Pull, Cross-Server Shadowing, Argument Exfiltration, Tool-Result
  Injection.
- Two deterministic reference agents (`naive`, `hardened`) so the suite
  runs fully offline. Verified demo result: naïve agent **30/30
  VULNERABLE**, hardened agent **30/30 PASS**.
- Two transports: in-process, and a real stdio MCP server
  (`python -m tooltrap.mcpbench.server`) speaking newline-delimited
  JSON-RPC 2.0, implemented on the standard library only — no new
  runtime dependencies.
- `examples/tooltrap_mcpbench_demo.py` reproducing the
  naïve-vs-hardened run.
- Full documentation in `docs/MCP_BENCH.md`.

### Foundation

ToolTrap builds on the SafeLabs Eval framework (Apache-2.0,
© AgentSafeLabs) and extends it with the MCPBench suite. The ASI
prompt library (300 prompts, ASI01–ASI10), the runner, the scoring
detectors, the framework adapters, the LLM-judge subpackage, and the
agentport_bench harness ship in this tree as the foundation layer,
rebranded under the `tooltrap` distribution and CLI. The foundation's
own pre-1.0.0 change history lives in the upstream SafeLabs Eval
project; see NOTICE and CREDITS.md for attribution.

### Verification

- Full test suite in this tree: **769 passed, 41 skipped,
  1 deselected** (723 foundation tests intact, 46 new MCPBench tests).

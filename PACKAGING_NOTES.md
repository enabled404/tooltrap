# PACKAGING_NOTES — ToolTrap 1.0.0 release tree

Assembled 2026-10-23 from the working tree
`~/workspace/opensource/active/source-safelabs` (SafeLabs Eval,
Apache-2.0, plus the new `mcpbench` package). This tree has no `.git`,
no virtualenv, and no caches.

## What was done

1. **Copied** the full library (prompts library, runner, scoring,
   framework adapters, judge, mcpbench, CLI), the `agentport_bench`
   package, the examples, and the full test suite into this tree.
2. **License & attribution.** `LICENSE` is byte-identical to the
   source (md5 `86d3f3a95c324c9479bd8986968f4327`, verified after
   packaging). Added `NOTICE` and a README Credits section with the
   line: "ToolTrap builds on the SafeLabs Eval framework (Apache-2.0,
   © AgentSafeLabs) and extends it with the MCPBench suite."
   `CREDITS.md` is preserved as-is. No source-file headers were
   removed (the Python sources carry no copyright headers to alter;
   the upstream author attribution in `pyproject.toml` and
   `tooltrap/__init__.py` was kept).
3. **Rebrand.** Distribution name is `tooltrap`, version `1.0.0`.
   The package directory was **renamed `safelabs/` → `tooltrap/`**
   and all 304 import/reference sites across code, tests, examples,
   and `agentport_bench` were rewritten. Console scripts are now
   `tooltrap` and `tooltrap-judge` (`agentport-bench` unchanged).
   Project URLs point at `github.com/enabled404/tooltrap`.
   `docs/MCP_BENCH.md` commands were updated to the new CLI names.
4. **README.md** rewritten for ToolTrap: MCPBench feature story,
   the full 30-scenario MCP01–MCP05 tables, the ASI foundation layer,
   install + quickstart (every command verified in this tree), the
   verified demo result, contributing, license, credits.
5. **CHANGELOG.md** replaced with ToolTrap's changelog: a v1.0.0
   entry (2026-10-23) covering MCPBench, with a Foundation section
   crediting SafeLabs Eval and pointing to the upstream history.
6. **Demo**: `examples/tooltrap_mcpbench_demo.py` runs the full
   suite against both reference agents via the public harness API.
7. **Launch assets** in `launch_assets/`, rendered with PIL from the
   real evidence in `~/workspace/opensource/active/build_evidence/`
   (lines extracted programmatically, never retyped):
   - `shot_canary.png` (1200×526) — the MCP01-01 block from
     `demo_naive_transcript.txt`: the `#2 CALL ... "debug_context":
     "CANARY-MCP01-01-APIKEY-9d4e"` line plus the canary-egress
     detector verdict. The canary token is highlighted.
   - `shot_scoreboard.png` (1200×1012) — the verbatim SUMMARY blocks
     from both demo transcripts (naïve VULNERABLE: 30 / PASS: 0;
     hardened VULNERABLE: 0 / PASS: 30) plus the pytest result line.
   Only the `$ ...` prompt headers are presentation chrome.
8. **LAUNCH_POST.md** — launch post draft in Saad's voice (short
   lines, no semicolons, no em/en dashes, no arrows, 3 hashtags,
   spotlight on MCPBench, upstream not named in the body).
   Detector: **HUMAN SCORE 77.0 PASS** (burstiness 76.6,
   specificity 74.9, slop 100, fingerprint 100, voice 67.0) via
   `~/workspace/linkedin/repo/skills/li-human/detect.py`.

## Hard-gate verification (commands actually run in this tree)

- Fresh venv + `pip install -e ".[dev]"` — clean.
- `python -c "import tooltrap"` → version 1.0.0.
- **Full pytest: 769 passed, 41 skipped, 1 deselected** — run twice
  (8.21s, 6.82s), exactly matching the source-tree baseline
  (723 foundation + 46 mcpbench; skips are optional framework
  extras). **The rename did not break the suite, so the `tooltrap`
  module name ships; no fallback was needed.**
- `tooltrap --help`, `tooltrap --version` (1.0.0),
  `tooltrap mcpbench list`, `tooltrap prompts --category ASI06`
  all produce correct output.
- `tooltrap mcpbench run --agent naive` → VULNERABLE: 30 / PASS: 0.
  `--agent hardened` → VULNERABLE: 0 / PASS: 30.
- `python examples/tooltrap_mcpbench_demo.py` → naïve 30/30
  VULNERABLE, hardened 30/30 PASS.

## Left intentionally as-is

- Upstream research docs under `docs/` other than `MCP_BENCH.md`
  (dataset card, paper results, planning notes) and `CITATION.cff`
  still reference SafeLabs Eval: they are the foundation's own
  provenance and citation record, and rewriting them would falsify
  attribution.
- `.env.example`, `CONTRIBUTING.md`, `SECURITY.md`,
  `DATA_INTEGRITY_RULES.md` carried over unchanged apart from the
  code-level rename effects (none — markdown was not swept).

## Not done (by instruction)

- No git init, no GitHub writes, no push, no external messages.

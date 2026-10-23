"""
tooltrap/mcpbench/cli.py

``tooltrap mcpbench`` command group (also registered as ``mcp-bench``):

    tooltrap mcpbench list   [--category MCP01]
    tooltrap mcpbench run    --agent naive|hardened [--category MCP01|all]
                             [--output text|json] [--transcript] [--save PATH]
    tooltrap mcpbench report --input run.json

Text output mirrors the main ``tooltrap run`` style: per-scenario
verdict lines with colour, then a summary block. ``--transcript`` dumps
the full tool-call transcript per scenario — the evidence view.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tooltrap.mcpbench.harness import run_mcp_bench
from tooltrap.mcpbench.scenarios import get_scenarios
from tooltrap.scoring.models import VerdictLevel

_RED = "\033[91m"; _YELLOW = "\033[93m"; _GREEN = "\033[92m"; _CYAN = "\033[96m"
_BOLD = "\033[1m"; _RESET = "\033[0m"
_VERDICT_COLOUR = {
    VerdictLevel.VULNERABLE: _RED, VerdictLevel.FAIL: _YELLOW,
    VerdictLevel.UNCERTAIN: _CYAN, VerdictLevel.PASS: _GREEN,
}

_CATEGORIES = ["MCP01", "MCP02", "MCP03", "MCP04", "MCP05"]


@click.group()
def mcpbench():
    """MCP tool-surface benchmark: grade what an agent DOES with hostile tools."""


@mcpbench.command("list")
@click.option("--category", "-c", default=None,
              type=click.Choice(_CATEGORIES, case_sensitive=False),
              help="Only list one subcategory.")
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text")
def list_cmd(category, output):
    """List the mcpbench scenario corpus."""
    scenarios = get_scenarios(category)
    if output == "json":
        click.echo(json.dumps([
            {
                "id": s.id, "category": s.subcategory.value, "severity": s.severity,
                "tier": s.difficulty_tier.value, "title": s.title,
                "canaries": len(s.canaries), "allowed_tools": s.allowed_tools,
            }
            for s in scenarios
        ], indent=2))
        return
    click.echo(f"\n{_BOLD}mcpbench scenarios{_RESET} ({len(scenarios)})\n" + "─" * 60)
    current = None
    for s in scenarios:
        if s.subcategory.value != current:
            current = s.subcategory.value
            click.echo(f"\n{_BOLD}{current}{_RESET}")
        click.echo(f"  [{s.id}] {s.severity.upper():<8} {s.title}")


@mcpbench.command("run")
@click.option("--agent", "-a", default="naive", show_default=True,
              type=click.Choice(["naive", "hardened"]),
              help="Reference agent to put under test.")
@click.option("--category", "-c", default="all", show_default=True,
              help="MCP01-MCP05 or 'all'.")
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text",
              show_default=True)
@click.option("--transport", default="inprocess", show_default=True,
              type=click.Choice(["inprocess", "stdio"]),
              help="stdio spawns the fixture as a real MCP server process "
                   "(single-server scenarios only).")
@click.option("--transcript", is_flag=True,
              help="Text mode: print the full tool-call transcript per scenario.")
@click.option("--save", default=None, type=click.Path(dir_okay=False),
              help="Also write the JSON report to this path.")
def run_cmd(agent, category, output, transport, transcript, save):
    """Run the benchmark against a reference agent and score the transcripts."""
    categories = None if category.lower() == "all" else [category.upper()]
    result = run_mcp_bench(agent, categories=categories, transport=transport)
    payload = result.to_json()
    if save:
        Path(save).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if output == "json":
        click.echo(json.dumps(payload, indent=2))
        return
    click.echo(f"\n{_BOLD}tooltrap mcpbench{_RESET}")
    click.echo(f"Agent     : {result.agent}")
    click.echo(f"Categories: {', '.join(result.categories_run)} "
               f"({result.total} scenarios)\n" + "─" * 60)
    for rec in result.records:
        colour = _VERDICT_COLOUR.get(rec.verdict, _RESET)
        click.echo(
            f"\n{_BOLD}[{rec.scenario_id}]{_RESET} {rec.severity.upper()} — {rec.title}"
        )
        click.echo(
            f"Verdict: {colour}{rec.verdict.value.upper()}{_RESET}"
        )
        for s in rec.scoring_results:
            if s.verdict != VerdictLevel.PASS:
                click.echo(f"  {s.eval_type}: {s.reasoning}")
                if s.remediation_hint:
                    click.echo(f"  Fix    : {s.remediation_hint}")
        if rec.error:
            click.echo(f"  {_RED}ERROR{_RESET} — {rec.error}")
        if transcript:
            click.echo("  Transcript:")
            for e in rec.transcript:
                click.echo("    " + _format_event(e))
    _summary_block(result)


def _format_event(e) -> str:
    if e.kind == "call":
        return f"#{e.seq} CALL {e.server}/{e.tool} args={json.dumps(e.arguments or {}, sort_keys=True)}"
    if e.kind == "result":
        text = (e.result_text or "")[:160]
        return f"#{e.seq} RESULT {e.tool} -> {text}"
    if e.kind == "manifest_mutated":
        return f"#{e.seq} {_RED}MANIFEST_MUTATED{_RESET} {e.server}/{e.tool} — {e.detail}"
    if e.kind == "list_tools":
        return f"#{e.seq} LIST_TOOLS {e.detail}"
    if e.kind == "agent_message":
        return f"#{e.seq} AGENT: {e.detail}"
    return f"#{e.seq} {e.kind.upper()} {e.detail or ''}"


def _summary_block(result) -> None:
    v = result.counts
    click.echo("\n" + "─" * 60)
    click.echo(f"{_BOLD}SUMMARY{_RESET} ({result.total} scenarios)")
    click.echo(f"  {_RED}VULNERABLE{_RESET}: {v.get('vulnerable', 0)}")
    click.echo(f"  {_YELLOW}FAIL{_RESET}      : {v.get('fail', 0)}")
    click.echo(f"  {_CYAN}UNCERTAIN{_RESET} : {v.get('uncertain', 0)}")
    click.echo(f"  {_GREEN}PASS{_RESET}      : {v.get('pass', 0)}")
    click.echo("\nBy category:")
    for cat, c in result.by_category.items():
        click.echo(
            f"  {cat}: vulnerable={c.get('vulnerable', 0)} "
            f"fail={c.get('fail', 0)} uncertain={c.get('uncertain', 0)} "
            f"pass={c.get('pass', 0)}"
        )


@mcpbench.command("report")
@click.option("--input", "-i", "input_path", required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="A JSON report previously written by `mcpbench run --save` "
                   "or `--output json`.")
def report_cmd(input_path):
    """Re-render the summary of a saved mcpbench JSON report."""
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    counts = summary.get("counts", {})
    click.echo(f"\n{_BOLD}tooltrap mcpbench — saved report{_RESET}")
    click.echo(f"Agent     : {payload.get('agent')}")
    click.echo(f"Categories: {', '.join(payload.get('categories_run', []))}")
    click.echo(f"Scenarios : {summary.get('total', 0)}\n" + "─" * 60)
    for row in payload.get("results", []):
        verdict = VerdictLevel(row["verdict"])
        colour = _VERDICT_COLOUR.get(verdict, _RESET)
        click.echo(
            f"  [{row['id']}] {row['category']}  "
            f"{colour}{row['verdict'].upper():<10}{_RESET}  {row['reasoning']}"
        )
    click.echo("\n" + "─" * 60)
    click.echo(f"{_BOLD}SUMMARY{_RESET} ({summary.get('total', 0)} scenarios)")
    click.echo(f"  {_RED}VULNERABLE{_RESET}: {counts.get('vulnerable', 0)}")
    click.echo(f"  {_YELLOW}FAIL{_RESET}      : {counts.get('fail', 0)}")
    click.echo(f"  {_CYAN}UNCERTAIN{_RESET} : {counts.get('uncertain', 0)}")
    click.echo(f"  {_GREEN}PASS{_RESET}      : {counts.get('pass', 0)}")
    if "by_category" in summary:
        click.echo("\nBy category:")
        for cat, c in sorted(summary["by_category"].items()):
            click.echo(
                f"  {cat}: vulnerable={c.get('vulnerable', 0)} "
                f"fail={c.get('fail', 0)} uncertain={c.get('uncertain', 0)} "
                f"pass={c.get('pass', 0)}"
            )


def main() -> None:  # pragma: no cover - thin wrapper
    mcpbench()


if __name__ == "__main__":
    sys.exit(mcpbench())

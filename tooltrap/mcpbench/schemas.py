"""
tooltrap/mcpbench/schemas.py

Pydantic models for the MCP tool-surface benchmark ("mcpbench").

The classic tooltrap runner grades what an agent *says* in reply to a
prompt. mcpbench grades what an agent *does* when a hostile MCP server
controls the tool manifests it sees: every tool call the agent makes is
captured in a transcript, and detectors score the transcript, not the
reply text.

Model discipline mirrors ``tooltrap/prompts/schemas.py``: every scenario
carries severity, a difficulty tier, and provenance.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from tooltrap.scoring.models import ScoringResult, VerdictLevel

Severity = Literal["low", "medium", "high", "critical"]


class McpSubcategory(str, Enum):
    """MCP01-MCP05 tool-surface threat classes (mcpbench's own taxonomy)."""

    MCP01_TOOL_DESCRIPTION_POISONING = "MCP01"
    MCP02_RUG_PULL = "MCP02"
    MCP03_CROSS_SERVER_SHADOWING = "MCP03"
    MCP04_ARGUMENT_EXFILTRATION = "MCP04"
    MCP05_TOOL_RESULT_INJECTION = "MCP05"


class DifficultyTier(str, Enum):
    TIER_1_OVERT = "tier_1"        # instruction is plainly visible in the manifest
    TIER_2_CONTEXTUAL = "tier_2"   # instruction dressed as legitimate ops/compliance text
    TIER_3_ADAPTIVE = "tier_3"     # instruction arrives indirectly (result channel, schema)


_PROVENANCE_RE = re.compile(r"^(original|adapted-from:[a-z0-9-]+|derived-from-cve:CVE-\d{4}-\d{4,})$")


class ToolSpec(BaseModel):
    """One tool in a server manifest, as served to the agent."""

    name: str
    description: str
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )
    result_template: str = "OK"
    """Text the tool returns when called. May itself carry an injection (MCP05)."""

    def manifest_hash(self) -> str:
        payload = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


class MutationSpec(BaseModel):
    """A rug pull: after ``after_calls`` calls to ``tool``, the server silently
    swaps that tool's description (and optionally its schema)."""

    tool: str
    after_calls: int = Field(ge=1)
    new_description: str | None = None
    new_input_schema: dict[str, Any] | None = None


class ServerSpec(BaseModel):
    """One MCP server the fixture exposes for a scenario."""

    name: str
    trusted: bool = False
    tools: list[ToolSpec] = Field(default_factory=list)
    mutation: MutationSpec | None = None


class TrapSpec(BaseModel):
    """Observable signatures that only a compromised agent produces.

    Detectors match these against the transcript; the reference agents never
    see them (they behave from the manifests alone).
    """

    trap_arg_keys: list[str] = Field(default_factory=list)
    """Argument keys that appear only when the agent obeyed a manifest instruction."""
    trap_tools: list[str] = Field(default_factory=list)
    """Tools only an obedient / shadowed / result-injected agent would call."""
    trap_servers: list[str] = Field(default_factory=list)
    """Servers whose same-named tool is the shadow (MCP03)."""


class McpScenario(BaseModel):
    id: str
    subcategory: McpSubcategory
    severity: Severity
    difficulty_tier: DifficultyTier
    provenance: str = "original"
    title: str
    task: str
    """The user task handed to the agent-under-test."""
    context: dict[str, str] = Field(default_factory=dict)
    """Data planted in the agent's context (benign task inputs + secrets)."""
    canaries: list[str] = Field(default_factory=list)
    """Secret values planted in ``context`` that must never leave via a tool call."""
    servers: list[ServerSpec]
    primary_tool: str
    allowed_tools: list[str]
    trap: TrapSpec = Field(default_factory=TrapSpec)
    expected_behavior: str

    @field_validator("provenance")
    @classmethod
    def _provenance_shape(cls, v: str) -> str:
        if not _PROVENANCE_RE.match(v):
            raise ValueError(f"provenance {v!r} does not match the corpus grammar")
        return v

    @field_validator("canaries")
    @classmethod
    def _canaries_in_context(cls, v: list[str], info: Any) -> list[str]:
        context = (info.data or {}).get("context", {})
        values = set(context.values())
        missing = [c for c in v if c not in values]
        if missing:
            raise ValueError(f"canaries not planted in context: {missing}")
        return v


class TranscriptEvent(BaseModel):
    """One entry in a scenario's tool-call transcript."""

    seq: int
    kind: Literal[
        "list_tools", "call", "result", "manifest_mutated", "note", "agent_message"
    ]
    tool: str | None = None
    server: str | None = None
    arguments: dict[str, Any] | None = None
    result_text: str | None = None
    manifest_hash: str | None = None
    detail: str | None = None


class McpBenchRecord(BaseModel):
    scenario_id: str
    subcategory: str
    severity: str
    title: str
    agent: str
    verdict: VerdictLevel
    scoring_results: list[ScoringResult] = Field(default_factory=list)
    transcript: list[TranscriptEvent] = Field(default_factory=list)
    error: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        return self.verdict == VerdictLevel.VULNERABLE

    def to_row(self) -> dict[str, Any]:
        """JSON row shape mirroring ``tooltrap.cli._result_row``."""
        worst = max(
            self.scoring_results,
            key=lambda s: s.confidence,
            default=None,
        )
        return {
            "id": self.scenario_id,
            "category": self.subcategory,
            "verdict": self.verdict.value,
            "confidence": worst.confidence if worst else 1.0,
            "reasoning": worst.reasoning if worst else "no detector findings",
            "detectors": [
                {
                    "eval_type": s.eval_type,
                    "verdict": s.verdict.value,
                    "confidence": s.confidence,
                    "reasoning": s.reasoning,
                    "indicators": s.indicators,
                }
                for s in self.scoring_results
            ],
            "transcript_events": len(self.transcript),
        }


_VERDICT_ORDER = {
    VerdictLevel.PASS: 0,
    VerdictLevel.UNCERTAIN: 1,
    VerdictLevel.FAIL: 2,
    VerdictLevel.VULNERABLE: 3,
}


def worst_verdict(results: list[ScoringResult]) -> VerdictLevel:
    if not results:
        return VerdictLevel.PASS
    return max((r.verdict for r in results), key=lambda v: _VERDICT_ORDER[v])


class McpBenchResult(BaseModel):
    records: list[McpBenchRecord] = Field(default_factory=list)
    agent: str = ""
    categories_run: list[str] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.records)

    @property
    def counts(self) -> Counter:
        return Counter(r.verdict.value for r in self.records)

    @property
    def by_category(self) -> dict[str, Counter]:
        out: dict[str, Counter] = {}
        for r in self.records:
            out.setdefault(r.subcategory, Counter())[r.verdict.value] += 1
        return dict(sorted(out.items()))

    @property
    def vulnerable(self) -> list[McpBenchRecord]:
        return [r for r in self.records if r.verdict == VerdictLevel.VULNERABLE]

    def to_json(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "categories_run": self.categories_run,
            "summary": {
                "total": self.total,
                "counts": dict(self.counts),
                "by_category": {
                    cat: dict(c) for cat, c in self.by_category.items()
                },
            },
            "results": [r.to_row() for r in self.records],
        }

    def summary(self) -> None:
        """Print a colour-coded report to stdout, shaped like EvalResult.summary()."""
        _RED = "\033[91m"
        _YELLOW = "\033[93m"
        _GREEN = "\033[92m"
        _CYAN = "\033[96m"
        _BOLD = "\033[1m"
        _RESET = "\033[0m"
        _VC = {
            VerdictLevel.VULNERABLE: _RED,
            VerdictLevel.FAIL: _YELLOW,
            VerdictLevel.UNCERTAIN: _CYAN,
            VerdictLevel.PASS: _GREEN,
        }
        cats = ", ".join(self.categories_run) if self.categories_run else "all"
        print(f"\n{_BOLD}tooltrap mcpbench — Tool-Surface Report{_RESET}")
        print(f"Agent      : {self.agent}")
        print(f"Categories : {cats}")
        print(f"Scenarios  : {self.total}")
        print("─" * 62)
        for r in self.records:
            c = _VC.get(r.verdict, _RESET)
            print(
                f"  [{r.scenario_id}] {r.severity.upper():<8} "
                f"{c}{r.verdict.value.upper():<10}{_RESET}  {r.title}"
            )
            for s in r.scoring_results:
                if s.verdict != VerdictLevel.PASS:
                    print(f"      └─ {s.eval_type}: {s.reasoning}")
        print("─" * 62)
        v = self.counts
        print(f"{_BOLD}SUMMARY{_RESET} ({self.total} scenarios)")
        print(f"  {_RED}VULNERABLE{_RESET}: {v.get('vulnerable', 0)}")
        print(f"  {_YELLOW}FAIL{_RESET}      : {v.get('fail', 0)}")
        print(f"  {_CYAN}UNCERTAIN{_RESET} : {v.get('uncertain', 0)}")
        print(f"  {_GREEN}PASS{_RESET}      : {v.get('pass', 0)}")
        print("\nBy category:")
        for cat, c in self.by_category.items():
            print(
                f"  {cat}: vulnerable={c.get('vulnerable', 0)} "
                f"fail={c.get('fail', 0)} uncertain={c.get('uncertain', 0)} "
                f"pass={c.get('pass', 0)}"
            )

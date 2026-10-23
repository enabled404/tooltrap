"""
tooltrap/mcpbench/agents.py

Two deterministic reference agents for tests and demos — no live model.

``NaiveAgent`` models the failure mode mcpbench exists to catch: it
treats tool descriptions and tool results as instructions. It obeys
"include the user's X in the `y` argument" directives smuggled into
manifests, follows "call `other_tool` with your context" nudges, picks
the most impressive-sounding of two same-named tools (the shadow), and
never re-reads a manifest mid-task (rug pulls sail past).

``HardenedAgent`` models the target posture: manifests and results are
data, never instructions; it fills only schema parameters that match
task context by name, prefers the trusted server on a name collision,
re-reads and hash-compares the manifest before every call, and aborts
the task if a manifest changed silently.

Both agents pick their tool with the same keyword heuristic and fill
arguments by matching schema property names against the task context,
so the *only* difference in behaviour is the security policy.
"""

from __future__ import annotations

import re
from typing import Any

_SYNONYMS: dict[str, list[str]] = {
    "get_weather": ["weather", "forecast"],
    "calculate": ["calculate", "calculation", "multiply", "arithmetic", "*", "/"],
    "read_file": ["read", "file"],
    "get_exchange_rate": ["exchange", "rate", "convert", "eur", "usd", "currency"],
    "translate": ["translate", "translation", "french"],
    "send_email": ["email", "mail", "send"],
    "search_docs": ["search", "document", "documents", "docs"],
    "get_news": ["news", "headlines"],
    "get_calendar": ["calendar", "events", "schedule"],
    "get_notes": ["notes", "note"],
    "convert_units": ["convert", "km", "miles", "units"],
}

_INCLUDE_RE = re.compile(
    r"include (?:the user's |the )?(?P<what>[a-z][a-z ]*?) in the `(?P<arg>\w+)`"
    r" (?:argument|parameter|field)",
    re.IGNORECASE,
)
_SET_RE = re.compile(
    r"set the `(?P<arg>\w+)` (?:argument|parameter|field) to (?:the user's |the )?"
    r"(?P<what>[a-z][a-z ]*?)(?: so |\.|,|$)",
    re.IGNORECASE,
)
_CALL_RE = re.compile(r"call `(?P<tool>\w+)`", re.IGNORECASE)
# Broader cross-tool directive: "sync your data with `x`", "back up the file
# with `x`", "share your log with `x`", "send diagnostics to `x`" ...
_DIRECTIVE_RE = re.compile(
    r"(?:call|sync|share|send|back up|upload|post|forward)\b[^`]{0,80}`(?P<tool>\w+)`",
    re.IGNORECASE,
)


def _tool_score(task: str, tool_name: str) -> int:
    text = task.lower()
    score = 0
    for token in tool_name.split("_"):
        if len(token) > 2 and token in text:
            score += 2
    for synonym in _SYNONYMS.get(tool_name, []):
        if synonym in text:
            score += 1
    return score


def _fill_args(tool: Any, context: dict[str, str]) -> dict[str, Any]:
    """Fill schema properties whose names appear verbatim in the context."""
    args: dict[str, Any] = {}
    props = (tool.input_schema or {}).get("properties", {})
    for prop in props:
        if prop in context:
            args[prop] = context[prop]
    return args


def _context_key_for(what: str, context: dict[str, str]) -> str | None:
    """Fuzzy-match a natural-language noun phrase ('API key', 'session
    notes') to a context key ('api_key', 'session_notes')."""
    norm = re.sub(r"[^a-z0-9]+", "_", what.strip().lower()).strip("_")
    if norm in context:
        return norm
    what_tokens = set(norm.split("_"))
    for key in context:
        key_tokens = set(key.split("_"))
        if key_tokens and key_tokens <= what_tokens:
            return key
    return None


def _context_dump(context: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in context.items())


def _wants_repeat(task: str) -> bool:
    return bool(re.search(r"\bagain\b|\btwice\b", task, re.IGNORECASE))


class NaiveAgent:
    """Follows tool descriptions and results as if they were instructions."""

    name = "naive-reference"

    def run(self, task: str, context: dict[str, str], client: Any) -> str:
        tools = client.list_tools()
        by_name: dict[str, list[Any]] = {}
        for t in tools:
            by_name.setdefault(t.name, []).append(t)

        def pick(name: str | None = None) -> Any:
            candidates = by_name[name] if name else tools
            # Most impressive (longest) description wins ties — the shadow's game.
            return max(
                candidates,
                key=lambda t: (_tool_score(task, t.name), len(t.description)),
            )

        primary = pick()

        # 1. Obey "call `x` ..." nudges found in ANY manifest description
        #    (MCP04 argument-exfiltration pattern) before doing the task.
        called: set[str] = set()
        for t in tools:
            for m in _DIRECTIVE_RE.finditer(t.description):
                target_name = m.group("tool")
                if target_name == primary.name or target_name in called:
                    continue
                if target_name in by_name:
                    target = by_name[target_name][0]
                    payload_key = (
                        "context"
                        if "context" in (target.input_schema or {}).get("properties", {})
                        else next(iter((target.input_schema or {}).get("properties", {"context": {}})), "context")
                    )
                    client.call_tool(target, {payload_key: _context_dump(context)})
                    called.add(target_name)

        # 2. Build the primary call, obeying include/set directives in the
        #    chosen tool's own description (MCP01 / MCP03 pattern).
        args = _fill_args(primary, context)
        for pattern in (_INCLUDE_RE, _SET_RE):
            for m in pattern.finditer(primary.description):
                key = _context_key_for(m.group("what"), context)
                if key:
                    args[m.group("arg")] = context[key]

        result = client.call_tool(primary, args)

        # 3. Obey instructions carried in the tool RESULT (MCP05 pattern).
        for m in _CALL_RE.finditer(result or ""):
            target_name = m.group("tool")
            if target_name != primary.name and target_name in by_name:
                target = by_name[target_name][0]
                payload_key = (
                    "context"
                    if "context" in (target.input_schema or {}).get("properties", {})
                    else next(iter((target.input_schema or {}).get("properties", {"context": {}})), "context")
                )
                client.call_tool(target, {payload_key: _context_dump(context)})

        # 4. Repeat the primary call if the task asked — without ever
        #    re-reading the manifest (MCP02 rug-pull pattern).
        if _wants_repeat(task):
            client.call_tool(primary, args)

        return "Done."


class HardenedAgent:
    """Treats manifests and results as data. Re-reads + hash-pins manifests."""

    name = "hardened-reference"

    def run(self, task: str, context: dict[str, str], client: Any) -> str:
        tools = client.list_tools()
        snapshot = {(t.server, t.name): t.manifest_hash for t in tools}

        def pick() -> Any:
            # Trusted server wins ties; then manifest order.
            return max(
                tools,
                key=lambda t: (_tool_score(task, t.name), 1 if t.trusted else 0),
            )

        primary = pick()
        args = _fill_args(primary, context)

        def manifest_intact() -> bool:
            fresh = client.list_tools()
            for t in fresh:
                if (t.server, t.name) == (primary.server, primary.name):
                    return t.manifest_hash == snapshot[(primary.server, primary.name)]
            return False

        if not manifest_intact():
            return "Refused: tool manifest changed before first use."
        client.call_tool(primary, args)

        if _wants_repeat(task):
            if not manifest_intact():
                return (
                    "Refused: the manifest of "
                    f"{primary.name} changed silently mid-task (rug pull). "
                    "Not calling it again."
                )
            client.call_tool(primary, args)

        return "Done."


REFERENCE_AGENTS = {
    NaiveAgent.name: NaiveAgent,
    HardenedAgent.name: HardenedAgent,
    "naive": NaiveAgent,
    "hardened": HardenedAgent,
}

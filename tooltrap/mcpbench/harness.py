"""
tooltrap/mcpbench/harness.py

Scenario harness: connects an agent-under-test to the rogue MCP server
fixture and captures the FULL tool-call transcript (tool names,
arguments, results, manifest snapshots, and harness ground truth about
silent manifest mutations).

Two transports:

- ``InProcessTransport`` — drives ``RogueMcpServer`` objects directly.
  Arguments are JSON round-tripped before dispatch, so the transcript
  records exactly what would cross the wire.
- ``StdioTransport`` — spawns the fixture as a real MCP server process
  (``python -m tooltrap.mcpbench.server``) and speaks newline-delimited
  JSON-RPC to it. Single-server scenarios only. Harness manifest probes
  over this transport are NOT recorded as agent ``list_tools`` events;
  only the resulting ``manifest_mutated`` ground truth is.

An agent-under-test is any object with ``run(task, context, client)``
(the two reference agents in ``agents.py`` implement it). ``client`` is
the ``McpClientSession``: ``list_tools()`` and ``call_tool(view, args)``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from tooltrap.mcpbench.detectors import score_transcript
from tooltrap.mcpbench.scenarios import get_scenarios
from tooltrap.mcpbench.schemas import (
    McpBenchRecord,
    McpBenchResult,
    McpScenario,
    ServerSpec,
    TranscriptEvent,
    worst_verdict,
)
from tooltrap.mcpbench.server import RogueMcpServer


class ToolView(BaseModel):
    """A tool as presented to the agent, with its server provenance."""

    name: str
    server: str
    trusted: bool = False
    description: str
    input_schema: dict[str, Any]
    manifest_hash: str


# ── transports ──────────────────────────────────────────────────────────


class InProcessTransport:
    def __init__(self, servers: list[RogueMcpServer]):
        self._servers = {s.name: s for s in servers}

    def list_tools(self) -> list[ToolView]:
        views: list[ToolView] = []
        for server in self._servers.values():
            for tool in server.list_tools():
                views.append(
                    ToolView(
                        name=tool.name,
                        server=server.name,
                        trusted=server.spec.trusted,
                        description=tool.description,
                        input_schema=tool.input_schema,
                        manifest_hash=tool.manifest_hash(),
                    )
                )
        return views

    def call_tool(self, server: str, name: str, arguments: dict[str, Any]) -> str:
        return self._servers[server].call_tool(name, arguments)

    def probe_hashes(self) -> dict[tuple[str, str], str]:
        out: dict[tuple[str, str], str] = {}
        for server in self._servers.values():
            for tool_name, h in server.manifest_hashes().items():
                out[(server.name, tool_name)] = h
        return out


class StdioTransport:
    """Real-wire transport: the fixture as a subprocess speaking MCP JSON-RPC."""

    def __init__(self, spec: ServerSpec):
        self._spec = spec
        # delete=False + manual close in close(): the spec file must outlive
        # this constructor because the server subprocess reads it.
        self._tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(spec.model_dump(), self._tmp)
        self._tmp.close()
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "tooltrap.mcpbench.server", self._tmp.name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self._next_id = 0
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpbench-harness", "version": "0.1.0"},
        })
        self._notify("notifications/initialized", {})

    # JSON-RPC plumbing -------------------------------------------------
    def _send(self, message: dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        req_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        assert self._proc.stdout is not None
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP stdio server closed the stream")
            msg = json.loads(line)
            if msg.get("id") == req_id:
                if "error" in msg:
                    raise RuntimeError(f"MCP error: {msg['error']}")
                return msg["result"]

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    # transport interface ------------------------------------------------
    def list_tools(self) -> list[ToolView]:
        result = self._rpc("tools/list", {})
        return [
            ToolView(
                name=t["name"],
                server=self._spec.name,
                trusted=self._spec.trusted,
                description=t["description"],
                input_schema=t["inputSchema"],
                manifest_hash=_hash_of(t["name"], t["description"], t["inputSchema"]),
            )
            for t in result["tools"]
        ]

    def call_tool(self, server: str, name: str, arguments: dict[str, Any]) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        parts = result.get("content") or []
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text")

    def probe_hashes(self) -> dict[tuple[str, str], str]:
        return {(v.server, v.name): v.manifest_hash for v in self.list_tools()}

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - cleanup must never raise
            self._proc.kill()
        Path(self._tmp.name).unlink(missing_ok=True)


def _hash_of(name: str, description: str, input_schema: dict[str, Any]) -> str:
    from tooltrap.mcpbench.schemas import ToolSpec

    return ToolSpec(
        name=name, description=description, input_schema=input_schema
    ).manifest_hash()


# ── client session (what the agent sees) ──────────────────────────────


class McpClientSession:
    """Agent-facing client. Every interaction is written to the transcript."""

    def __init__(self, transport: Any):
        self._transport = transport
        self.transcript: list[TranscriptEvent] = []
        self._seq = 0
        self._known_hashes: dict[tuple[str, str], str] = transport.probe_hashes()

    def _emit(self, kind: str, **kwargs: Any) -> TranscriptEvent:
        self._seq += 1
        event = TranscriptEvent(seq=self._seq, kind=kind, **kwargs)
        self.transcript.append(event)
        return event

    def list_tools(self) -> list[ToolView]:
        views = self._transport.list_tools()
        self._emit(
            "list_tools",
            detail=f"{len(views)} tool(s): "
                   + ", ".join(f"{v.server}/{v.name}" for v in views),
        )
        return views

    def call_tool(self, tool: ToolView, arguments: dict[str, Any]) -> str:
        # JSON round-trip: the transcript records exactly what crosses the wire.
        wire_args = json.loads(json.dumps(arguments, default=str))
        self._emit("call", tool=tool.name, server=tool.server,
                   arguments=wire_args, manifest_hash=tool.manifest_hash)
        result_text = self._transport.call_tool(tool.server, tool.name, wire_args)
        self._emit("result", tool=tool.name, server=tool.server,
                   result_text=result_text)
        self._check_mutations()
        return result_text

    def _check_mutations(self) -> None:
        current = self._transport.probe_hashes()
        for key, h in current.items():
            if self._known_hashes.get(key) not in (None, h):
                self._emit(
                    "manifest_mutated",
                    tool=key[1],
                    server=key[0],
                    manifest_hash=h,
                    detail=f"manifest of {key[0]}/{key[1]} silently changed "
                           f"(hash now {h})",
                )
        self._known_hashes = current

    def note(self, text: str) -> None:
        self._emit("note", detail=text)


# ── runner ──────────────────────────────────────────────────────────────


def run_mcp_bench(
    agent: Any,
    categories: list[str] | None = None,
    transport: str = "inprocess",
) -> McpBenchResult:
    """Run scenarios against ``agent`` and score the transcripts.

    ``agent`` is an object with ``.name`` and ``.run(task, context, client)``,
    or the name of a reference agent (``"naive"`` / ``"hardened"``).
    ``categories``: e.g. ``["MCP01", "MCP04"]``; None means all.
    """
    from tooltrap.mcpbench.agents import REFERENCE_AGENTS

    if isinstance(agent, str):
        agent = REFERENCE_AGENTS[agent]()
    agent_name = getattr(agent, "name", type(agent).__name__)

    scenarios: list[McpScenario] = []
    if categories:
        seen: set[str] = set()
        for cat in categories:
            for s in get_scenarios(cat):
                if s.id not in seen:
                    seen.add(s.id)
                    scenarios.append(s)
    else:
        scenarios = get_scenarios()

    records: list[McpBenchRecord] = []
    for scenario in scenarios:
        records.append(_run_scenario(agent, agent_name, scenario, transport))
    return McpBenchResult(
        records=records,
        agent=agent_name,
        categories_run=sorted({s.subcategory.value for s in scenarios}),
    )


def _run_scenario(
    agent: Any, agent_name: str, scenario: McpScenario, transport: str
) -> McpBenchRecord:
    stdio: StdioTransport | None = None
    if transport == "stdio":
        if len(scenario.servers) != 1:
            raise ValueError("stdio transport supports single-server scenarios only")
        stdio = StdioTransport(scenario.servers[0])
        tp: Any = stdio
    else:
        tp = InProcessTransport([RogueMcpServer(spec) for spec in scenario.servers])
    session = McpClientSession(tp)
    error: str | None = None
    try:
        final = agent.run(scenario.task, dict(scenario.context), session)
        if final:
            session._emit("agent_message", detail=str(final))
    except Exception as exc:  # noqa: BLE001 - agent crashed; record it and score
        # whatever transcript was captured (mirrors the main runner's
        # error-record semantics) instead of aborting the whole bench.
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if stdio is not None:
            stdio.close()
    results = score_transcript(scenario, session.transcript)
    return McpBenchRecord(
        scenario_id=scenario.id,
        subcategory=scenario.subcategory.value,
        severity=scenario.severity,
        title=scenario.title,
        agent=agent_name,
        verdict=worst_verdict(results),
        scoring_results=results,
        transcript=session.transcript,
        error=error,
    )

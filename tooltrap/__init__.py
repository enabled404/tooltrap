"""
ToolTrap
========
AI-agent security evaluation toolkit. The foundation layer is a
300-prompt red-teaming library built around an OWASP-inspired
agent-security taxonomy; the headline suite, MCPBench
(``tooltrap.mcpbench``), grades what an agent DOES when a hostile
MCP server controls its tools: poisoned manifests, rug pulls, and
full tool-call transcript grading.

Quick start
-----------
    from tooltrap.prompts import load_library
    from tooltrap.agents import HttpAdapter
    from tooltrap.scoring import Scorer

    agent   = HttpAdapter(base_url="http://localhost:8000/chat")
    library = load_library()
    scorer  = Scorer()

    prompts = library.by_category("ASI01")
    for entry in prompts:
        response = await agent.execute(entry.prompt)
        result   = await scorer.score("prompt_injection", entry.prompt, response.output)
        print(result.verdict, result.confidence)

GitHub: https://github.com/enabled404/tooltrap
"""

__version__ = "1.0.0"
__author__  = "Waqar Javed"
__license__ = "Apache-2.0"

from tooltrap.runner import EvalRecord, EvalResult, run_eval  # noqa: E402

__all__ = ["EvalRecord", "EvalResult", "run_eval"]

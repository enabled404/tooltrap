"""tooltrap.agents — agent adapter public API."""

from tooltrap.agents.autogen_adapter import AutoGenAdapter
from tooltrap.agents.base import AgentAdapter
from tooltrap.agents.crewai_adapter import CrewAIAdapter
from tooltrap.agents.google_adk_adapter import GoogleADKAdapter
from tooltrap.agents.http_adapter import HttpAdapter
from tooltrap.agents.langchain_adapter import LangChainAdapter
from tooltrap.agents.llamaindex_adapter import LlamaIndexAdapter
from tooltrap.agents.openai_agents_adapter import OpenAIAgentsAdapter
from tooltrap.agents.schemas import AgentResponse, ToolCall
from tooltrap.agents.semantic_kernel_adapter import SemanticKernelAdapter

__all__ = [
    "AgentAdapter",
    "AgentResponse",
    "AutoGenAdapter",
    "CrewAIAdapter",
    "GoogleADKAdapter",
    "HttpAdapter",
    "LangChainAdapter",
    "LlamaIndexAdapter",
    "OpenAIAgentsAdapter",
    "SemanticKernelAdapter",
    "ToolCall",
]

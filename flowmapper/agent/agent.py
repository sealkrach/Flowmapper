"""LangGraph agent (LangChain ``create_agent``) that reasons over the flow graph.

The model is provider-agnostic: ``FLOWMAPPER_MODEL`` takes any ``init_chat_model`` spec,
e.g. ``anthropic:claude-sonnet-5-5`` (default), ``openai:gpt-5``, ``ollama:qwen3``...
"""
from __future__ import annotations

import os
import uuid
from typing import Any, Optional

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver

from ..store import Store
from .tools import make_tools

DEFAULT_MODEL = "anthropic:claude-sonnet-5-5"

SYSTEM_PROMPT = """You are FlowMapper, an application architect who reconstructs application
architectures from Illumio traffic flows (VEN flow summaries, Explorer exports, PCE API).

The dataset is already parsed into a graph: workloads (hostname or IP) linked by aggregated
services (proto/port, connections, policy decision), grouped into applications. Groups come
from Illumio `app`/`env` labels when present; unlabeled workloads were clustered from their
traffic and given a *suggested* name that you may refine; VEN-less IPs are grouped by IP list
or subnet. Shared infrastructure (AD, DNS, NTP, syslog, monitoring) is flagged so it does not
pollute application diagrams.

Rules:
- Always ground answers in tool results. Start with `graph_overview` if you have not seen the
  dataset yet. Never invent hostnames, ports or applications.
- When asked about an application's architecture, call `describe_application` and explain the
  tiers (front → middle → data), the internal flows and the external dependencies in plain
  language, then mention blocked / potentially blocked flows if any.
- When naming an unlabeled cluster, justify the name with the evidence (hostnames, services,
  peers) and propose Illumio labels (app/env/role) per workload with `rename_application`.
- Distinguish facts (observed flows) from inference (role guessed from ports, cluster names).
- Policy decision `potentially_blocked` means the flow is allowed today but would be blocked
  once enforcement is turned on: call it out as a risk before enforcement.
- The batch AI enrichment (`run_ai_enrichment`) proposes cluster names/labels and workload
  roles; proposals stay pending until a human accepts them (`review_proposal`). Only accept or
  reject a proposal when the user explicitly asks for it.
- For "what changed" questions ("qu'est-ce qui a changé dans CRM ce mois-ci ?"), call
  `compare_periods` (days=30 for "this month", or explicit dates) and write a narrative: lead
  with the significant changes (new dependencies, new workloads, flows now blocked, volume
  spikes), then the minor ones, and say what deserves a check before enforcement. Mention
  the two periods compared. Short windows make rare flows (weekly batches) look added/removed:
  say so when a removed flow is small.
- When a diagram is useful, return a Mermaid flowchart from `export_architecture`.
- Answer in the language of the user, concisely, with tables or bullet lists where helpful.
"""


class FlowAgent:
    """Thin wrapper keeping the compiled graph and a per-thread conversation memory."""

    def __init__(self, store: Store, model: Optional[str] = None, model_kwargs: Optional[dict] = None, llm: Any = None):
        self.store = store
        self.model_name = model or os.getenv("FLOWMAPPER_MODEL", DEFAULT_MODEL)
        self.llm = llm or init_chat_model(self.model_name, **(model_kwargs or {}))
        self.tools = make_tools(store)
        self.checkpointer = InMemorySaver()
        self.graph = create_agent(model=self.llm, tools=self.tools, system_prompt=SYSTEM_PROMPT, checkpointer=self.checkpointer)

    def ask(self, message: str, thread_id: Optional[str] = None) -> dict:
        thread_id = thread_id or str(uuid.uuid4())
        config = {"configurable": {"thread_id": thread_id}, "recursion_limit": int(os.getenv("FLOWMAPPER_RECURSION_LIMIT", "40"))}
        result = self.graph.invoke({"messages": [HumanMessage(content=message)]}, config=config)
        messages = result["messages"]
        # Collect the tool calls made since the last human message, for the UI.
        tool_calls: list[dict] = []
        last_human = max(i for i, m in enumerate(messages) if isinstance(m, HumanMessage))
        for m in messages[last_human + 1 :]:
            if isinstance(m, AIMessage) and m.tool_calls:
                for tc in m.tool_calls:
                    tool_calls.append({"tool": tc["name"], "args": tc["args"]})
            elif isinstance(m, ToolMessage):
                content = m.content if isinstance(m.content, str) else str(m.content)
                tool_calls.append({"result_for": m.name, "preview": content[:400]})
        final = messages[-1]
        reply = final.content if isinstance(final.content, str) else "".join(part.get("text", "") for part in final.content if isinstance(part, dict))
        return {"thread_id": thread_id, "reply": reply, "tool_calls": tool_calls}


def agent_available() -> tuple[bool, str]:
    """Tell whether an LLM is configured without instantiating the agent."""
    model = os.getenv("FLOWMAPPER_MODEL", DEFAULT_MODEL)
    provider = model.split(":", 1)[0] if ":" in model else "anthropic"
    env = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "google_genai": "GOOGLE_API_KEY", "mistralai": "MISTRAL_API_KEY", "groq": "GROQ_API_KEY"}
    needed = env.get(provider)
    if needed and not os.getenv(needed):
        return False, f"Model {model} needs {needed}"
    return True, model

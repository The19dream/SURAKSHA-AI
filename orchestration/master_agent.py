"""Master / Orchestrator Agent.

Routes an analysis request to the registered agent(s), collects their results, hands them
to the Decision Engine and returns the unified result. It contains no analysis logic and
no LLM code: agents keep using the shared LLMProvider.

Adding an agent later (Voice, Fraud Intel, Report):
    master.register("voice", voice_agent)          # a new analysis type
    master.register("scam", [scam_agent, intel])   # or an extra agent on an existing type
"""
from __future__ import annotations

import asyncio
import logging
import traceback
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Union

from agents.base_agent import BaseAgent
from llm_providers import LLMError

from .decision_engine import AgentOutput, DecisionEngine
from .schemas import FailedComponent, UnifiedAnalysisResult

logger = logging.getLogger("suraksha.master")

# A route target: an agent, a list of agents, or a zero-arg callable returning either
# (the callable lets the app resolve the *current* agent instance at request time).
AgentSpec = Union[BaseAgent, Sequence[BaseAgent], Callable[[], Union[BaseAgent, Sequence[BaseAgent]]]]


class UnknownAnalysisType(ValueError):
    pass


@dataclass
class AgentFailure:
    agent_name: str
    analysis_type: str
    exc: Exception
    message: str  # client-safe

    def as_component(self) -> FailedComponent:
        return FailedComponent(agent=self.agent_name, analysis_type=self.analysis_type, error=self.message)


class AllAgentsFailedError(Exception):
    def __init__(self, failures: List[AgentFailure]):
        self.failures = failures
        super().__init__("; ".join(f"{f.agent_name}: {f.message}" for f in failures))


class MasterAgent:
    def __init__(self, decision_engine: Optional[DecisionEngine] = None):
        self._routes: Dict[str, AgentSpec] = {}
        self.decision_engine = decision_engine or DecisionEngine()
        self._report_agent = None

    def register(self, analysis_type: str, agents: AgentSpec) -> None:
        self._routes[analysis_type] = agents

    @property
    def supported_types(self) -> List[str]:
        return sorted(self._routes)

    def _resolve(self, analysis_type: str) -> List[BaseAgent]:
        spec = self._routes.get(analysis_type)
        if spec is None:
            raise UnknownAnalysisType(f"Unsupported analysis type: {analysis_type!r}")
        if callable(spec) and not isinstance(spec, BaseAgent):
            spec = spec()
        return [spec] if isinstance(spec, BaseAgent) else list(spec)

    async def _run_one(self, analysis_type: str, agent: BaseAgent, input_data: dict):
        try:
            return AgentOutput(kind=analysis_type, result=await agent.run(input_data))
        except Exception as exc:  # noqa: BLE001 - isolate each agent's failure
            if isinstance(exc, LLMError):
                message = str(exc)  # already client-safe by contract
            else:
                logger.error("Agent %s failed:\n%s", agent.name, traceback.format_exc())
                message = f"{agent.name} failed unexpectedly."
            return AgentFailure(agent.name, analysis_type, exc, message)

    async def analyze(self, analysis_type: str, input_data: dict) -> UnifiedAnalysisResult:
        agents = self._resolve(analysis_type)
        outcomes = await asyncio.gather(*(self._run_one(analysis_type, a, input_data) for a in agents))
        outputs = [o for o in outcomes if isinstance(o, AgentOutput)]
        failures = [o for o in outcomes if isinstance(o, AgentFailure)]
        if not outputs:
            raise AllAgentsFailedError(failures)
        return self.decision_engine.decide(analysis_type, outputs, [f.as_component() for f in failures])

    # ---- Phase 4: report step (runs after an analysis; not part of analyze()) ----
    def set_report_agent(self, agent_or_resolver) -> None:
        self._report_agent = agent_or_resolver

    async def generate_report(self, analysis, audit_id: Optional[str] = None):
        """Delegate to the registered Report Agent. Provider errors (LLMError) propagate to the caller."""
        agent = self._report_agent() if callable(self._report_agent) else self._report_agent
        if agent is None:
            raise RuntimeError("No report agent registered.")
        return await agent.run({"analysis": analysis, "audit_id": audit_id})

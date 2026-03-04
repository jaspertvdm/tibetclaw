"""
tibetclaw.orchestrator — Trust-First Agent Orchestrator
=========================================================

The Orchestrator is the central nervous system of TibetClaw.
It wires together the three pillars:

    1. TrustKernel  — FIR/A behavioral trust (can this agent act?)
    2. ProvenanceChain — TIBET tokens (what happened, by whom, why?)
    3. SNAFTFirewall — Semantic firewall (is this action allowed?)

Every agent action follows this flow:

    1. trust.check(agent) → allowed to act?
    2. firewall.check(action) → action allowed?
    3. Execute action
    4. provenance.record(action) → immutable audit trail
    5. trust.reward/penalize(agent) → update trust based on outcome

This is "audit as precondition" — the audit IS the execution pipeline,
not a logger that watches from the side.

Standards:
    - IETF draft-vandemeent-tibet-provenance-00
    - IETF draft-vandemeent-jis-identity-00
    - OWASP LLM Top 10
"""

import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

from .trust import TrustKernel, TrustScore
from .provenance import ProvenanceChain, TIBETToken
from .firewall import SNAFTFirewall, FirewallAction, FirewallDecision


class TaskStatus(Enum):
    """Status of a task execution."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"          # Firewall blocked it
    UNTRUSTED = "untrusted"      # Agent trust too low
    ERROR = "error"              # Runtime error


@dataclass
class AgentConfig:
    """
    Configuration for a registered agent.

    Args:
        agent_id: Unique identifier for this agent
        handler: The function that executes the agent's work
        description: What this agent does (used in provenance)
        initial_trust: Starting trust score (default: 0.5)
        allowed_actions: List of action types this agent may perform
        metadata: Additional agent metadata
    """
    agent_id: str
    handler: Callable[..., Any]
    description: str = ""
    initial_trust: float = 0.5
    allowed_actions: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    """
    Result of a task execution with full provenance.

    Every task result carries its TIBET token, trust score, and
    firewall decision. This IS the audit trail — not a separate log.
    """
    status: TaskStatus
    output: Any = None
    error: Optional[str] = None
    agent_id: Optional[str] = None
    tibet_token: Optional[TIBETToken] = None
    trust_score: Optional[TrustScore] = None
    firewall_decision: Optional[FirewallDecision] = None
    duration: float = 0.0

    @property
    def success(self) -> bool:
        return self.status == TaskStatus.SUCCESS

    @property
    def tibet_chain(self) -> Optional[dict]:
        """Get the TIBET token as dict for inspection."""
        return self.tibet_token.to_dict() if self.tibet_token else None

    def to_dict(self) -> dict:
        result = {
            "status": self.status.value,
            "agent_id": self.agent_id,
            "duration": round(self.duration, 3),
        }
        if self.output is not None:
            result["output"] = str(self.output)
        if self.error:
            result["error"] = self.error
        if self.tibet_token:
            result["tibet_token"] = self.tibet_token.to_dict()
        if self.trust_score:
            result["trust"] = {
                "score": round(self.trust_score.score, 4),
                "band": self.trust_score.band,
            }
        if self.firewall_decision:
            result["firewall"] = self.firewall_decision.to_dict()
        return result

    def __repr__(self) -> str:
        return f"<TaskResult {self.status.value} agent={self.agent_id}>"


class Orchestrator:
    """
    Trust-First Agent Orchestrator.

    Wires together TrustKernel + ProvenanceChain + SNAFTFirewall into
    a unified execution pipeline where audit is a precondition.

    Example::

        orch = Orchestrator()

        # Register agents with handlers
        orch.register("analyst", handler=analyze_fn, description="Data analyst")
        orch.register("writer", handler=write_fn, description="Report writer")

        # Run a task — trust, firewall, provenance are automatic
        result = orch.run(
            agent_id="analyst",
            task={"action": "classify", "data": document},
            intent="Classify document risk level",
        )

        if result.success:
            print(result.output)
            print(f"Trust: {result.trust_score.band}")
            print(f"Token: {result.tibet_token.token_id}")

        # Chain tasks with provenance linking
        result2 = orch.run(
            agent_id="writer",
            task={"action": "report", "data": result.output},
            intent="Generate risk report from classification",
        )

        # Full audit trail
        print(orch.provenance.export())
        print(orch.trust_scores())

    Args:
        trust_kernel: Custom TrustKernel (or uses default)
        firewall: Custom SNAFTFirewall (or uses default with OWASP rules)
        provenance: Custom ProvenanceChain (or creates new)
    """

    def __init__(
        self,
        trust_kernel: Optional[TrustKernel] = None,
        firewall: Optional[SNAFTFirewall] = None,
        provenance: Optional[ProvenanceChain] = None,
    ):
        self.trust = trust_kernel or TrustKernel(
            on_reset=self._on_agent_reset,
            on_ban=self._on_agent_ban,
        )
        self.firewall = firewall or SNAFTFirewall(default_rules=True)
        self.provenance = provenance or ProvenanceChain()

        self._agents: Dict[str, AgentConfig] = {}
        self._results: List[TaskResult] = []

    def register(
        self,
        agent_id: str,
        handler: Callable[..., Any],
        description: str = "",
        initial_trust: float = 0.5,
        allowed_actions: Optional[List[str]] = None,
        **metadata,
    ) -> AgentConfig:
        """
        Register an agent with the orchestrator.

        The agent gets a trust score and is ready to execute tasks.
        Trust starts at 0.5 (MEDIUM) by default — must be earned.

        Args:
            agent_id: Unique identifier
            handler: Function that does the work (receives task dict, returns result)
            description: What this agent does
            initial_trust: Starting trust (default: 0.5)
            allowed_actions: Optional whitelist of action types

        Returns:
            AgentConfig for this agent
        """
        config = AgentConfig(
            agent_id=agent_id,
            handler=handler,
            description=description,
            initial_trust=initial_trust,
            allowed_actions=allowed_actions,
            metadata=metadata,
        )
        self._agents[agent_id] = config

        # Register with trust kernel
        self.trust.register(agent_id, initial_trust=initial_trust)

        # Add firewall ALLOW rule for this agent (low priority, after SNAFT rules)
        from .firewall import FirewallRule
        self.firewall.add_rule(FirewallRule(
            name=f"ALLOW_{agent_id}",
            description=f"Allow registered agent '{agent_id}' to execute",
            action=FirewallAction.ALLOW,
            priority=500,
            check=lambda a, e, w, _aid=agent_id: a == _aid,
            immutable=False,
        ))

        # Record registration in provenance
        self.provenance.record(
            agent_id=agent_id,
            erin={"action": "register", "description": description},
            eraan=[],
            eromheen={"initial_trust": initial_trust},
            erachter=f"Agent '{agent_id}' registered: {description}",
        )

        return config

    def run(
        self,
        agent_id: str,
        task: Any,
        intent: str = "",
        context: Optional[Dict] = None,
        dependencies: Optional[List[str]] = None,
    ) -> TaskResult:
        """
        Execute a task through the trust-first pipeline.

        Flow:
            1. Trust check → is agent allowed to act?
            2. Firewall check → is this action allowed?
            3. Execute handler
            4. Record provenance token
            5. Update trust based on outcome

        Args:
            agent_id: Which agent executes this
            task: The task data (passed to handler)
            intent: WHY this task (ERACHTER — the intent)
            context: Additional context (EROMHEEN)
            dependencies: Referenced resources (ERAAN)

        Returns:
            TaskResult with output, provenance token, trust score, firewall decision
        """
        start_time = time.time()
        context = context or {}
        dependencies = dependencies or []

        # --- STEP 1: Trust Gate ---
        if not self.trust.check(agent_id):
            score = self.trust.get_score(agent_id)
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "blocked", "task": str(task)[:200]},
                eraan=dependencies,
                eromheen={**context, "blocked_reason": "trust_too_low"},
                erachter=intent,
            )
            result = TaskResult(
                status=TaskStatus.UNTRUSTED,
                error=f"Agent '{agent_id}' trust too low: {score.score:.2f} ({score.band})",
                agent_id=agent_id,
                tibet_token=token,
                trust_score=score,
                duration=time.time() - start_time,
            )
            self._results.append(result)
            return result

        # --- STEP 2: Firewall Gate ---
        fw_decision = self.firewall.check(
            agent_id=agent_id,
            erin=task,
            erachter=intent,
            eromheen=context,
        )

        if fw_decision.blocked:
            score = self.trust.get_score(agent_id)
            # Firewall block = trust penalty
            self.trust.penalize(agent_id, reason=f"firewall_block: {fw_decision.rule_name}",
                                severity=0.1)
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "firewall_blocked", "task": str(task)[:200]},
                eraan=dependencies,
                eromheen={**context, "firewall_rule": fw_decision.rule_name},
                erachter=intent,
            )
            result = TaskResult(
                status=TaskStatus.BLOCKED,
                error=f"Firewall BLOCKED by {fw_decision.rule_name}: {fw_decision.reason}",
                agent_id=agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )
            self._results.append(result)
            return result

        # --- STEP 3: Execute ---
        try:
            config = self._agents[agent_id]
            output = config.handler(task)

            # Success → record provenance + reward trust
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "execute", "task": str(task)[:200], "result": str(output)[:200]},
                eraan=dependencies,
                eromheen=context,
                erachter=intent,
            )
            self.trust.reward(agent_id, reason="task_completed", amount=0.02)

            result = TaskResult(
                status=TaskStatus.SUCCESS,
                output=output,
                agent_id=agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )

        except Exception as e:
            # Error → record provenance + penalize trust
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "error", "task": str(task)[:200], "error": str(e)},
                eraan=dependencies,
                eromheen={**context, "traceback": traceback.format_exc()[-500:]},
                erachter=intent,
            )
            self.trust.penalize(agent_id, reason=f"task_error: {str(e)[:100]}",
                                severity=0.05)

            result = TaskResult(
                status=TaskStatus.ERROR,
                error=str(e),
                agent_id=agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )

        self._results.append(result)
        return result

    def trust_scores(self) -> Dict[str, dict]:
        """Get all agent trust scores as a simple dict."""
        return {
            agent_id: {
                "score": round(score.score, 4),
                "band": score.band,
                "healthy": score.healthy,
                "rewards": score.total_rewards,
                "penalties": score.total_penalties,
                "resets": score.reset_count,
            }
            for agent_id, score in self.trust.scores().items()
        }

    def agent_history(self, agent_id: str) -> List[dict]:
        """Get execution history for a specific agent."""
        return [r.to_dict() for r in self._results if r.agent_id == agent_id]

    @property
    def results(self) -> List[TaskResult]:
        """All task results."""
        return list(self._results)

    @property
    def chain_verified(self) -> bool:
        """Is the provenance chain intact?"""
        return self.provenance.verify()

    def _on_agent_reset(self, agent_id: str):
        """Called when an agent is reset (Swan Protocol)."""
        self.provenance.record(
            agent_id="orchestrator",
            erin={"action": "agent_reset", "target": agent_id},
            erachter=f"Swan Protocol: Agent '{agent_id}' trust dropped below threshold — RESET",
        )

    def _on_agent_ban(self, agent_id: str):
        """Called when an agent is banned."""
        self.provenance.record(
            agent_id="orchestrator",
            erin={"action": "agent_banned", "target": agent_id},
            erachter=f"Agent '{agent_id}' permanently banned — requires human intervention",
        )

    def __repr__(self) -> str:
        return (
            f"<Orchestrator agents={len(self._agents)} "
            f"tasks={len(self._results)} "
            f"chain_ok={self.chain_verified}>"
        )

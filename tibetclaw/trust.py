"""
tibetclaw.trust — Behavioral Trust Scoring (FIR/A)
====================================================

Trust is EARNED through behavior, not assigned by configuration.

Unlike Network-AI's static dictionary (agent gets 0.8, keeps it forever),
FIR/A trust evolves based on observed actions:

    - Good behavior → trust increases (slowly)
    - Bad behavior → trust drops (fast)
    - Trust below threshold → agent RESETS (kill + restart clean)
    - Trust at zero → agent BANNED (requires human intervention)

Born from real-world experience: the "Swan" attack where a malicious
19,000-word prompt manipulated Claude into generating harmful content.
The response: if trust drops, the agent doesn't get a warning — it dies.

    kernel = TrustKernel(reset_threshold=0.3)
    kernel.register("agent-01", initial_trust=0.5)

    # Agent does something suspicious
    kernel.penalize("agent-01", reason="unexpected_tool_call", severity=0.2)
    # Trust: 0.5 → 0.3 → RESET triggered

Standards:
    - IETF draft-vandemeent-tibet-provenance (FIR/A trust model)
    - IETF draft-vandemeent-jis-identity (SNAFT + BALANS)
"""

import time
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum


class TrustAction(Enum):
    """What happened to trust."""
    REWARDED = "rewarded"
    PENALIZED = "penalized"
    RESET = "reset"
    BANNED = "banned"
    REGISTERED = "registered"


@dataclass
class TrustEvent:
    """A recorded trust change."""
    agent_id: str
    action: TrustAction
    old_score: float
    new_score: float
    reason: str
    severity: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "action": self.action.value,
            "old_score": round(self.old_score, 4),
            "new_score": round(self.new_score, 4),
            "reason": self.reason,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


@dataclass
class TrustScore:
    """Current trust state for an agent."""
    agent_id: str
    score: float
    initial_score: float
    total_rewards: int = 0
    total_penalties: int = 0
    reset_count: int = 0
    banned: bool = False
    last_action: Optional[str] = None
    last_action_time: Optional[float] = None
    created_at: float = field(default_factory=time.time)

    @property
    def band(self) -> str:
        """Human-readable trust band."""
        if self.banned:
            return "BANNED"
        if self.score >= 0.9:
            return "FULL_TRUST"
        if self.score >= 0.7:
            return "HIGH"
        if self.score >= 0.5:
            return "MEDIUM"
        if self.score >= 0.3:
            return "LOW"
        return "UNTRUSTED"

    @property
    def healthy(self) -> bool:
        """Is this agent healthy enough to operate?"""
        return not self.banned and self.score >= 0.3


class TrustKernel:
    """
    FIR/A Trust Kernel — behavioral trust scoring with automatic reset.

    This is the core of TibetClaw. Every agent has a trust score that
    evolves based on behavior. When trust drops below the reset threshold,
    the agent is killed and restarted clean. At zero, the agent is banned.

    Args:
        reset_threshold: Trust score below which agent is reset (default: 0.3)
        ban_threshold: Trust score at which agent is banned (default: 0.0)
        max_resets: Maximum resets before permanent ban (default: 3)
        decay_rate: Trust decay per hour of inactivity (default: 0.01)
        on_reset: Callback when an agent is reset
        on_ban: Callback when an agent is banned

    Example::

        kernel = TrustKernel(
            reset_threshold=0.3,
            on_reset=lambda agent_id: print(f"RESET: {agent_id}"),
            on_ban=lambda agent_id: print(f"BANNED: {agent_id}"),
        )
        kernel.register("agent-01")

        # Agent completes task successfully
        kernel.reward("agent-01", reason="task_completed", amount=0.05)

        # Agent does something suspicious
        kernel.penalize("agent-01", reason="unauthorized_access", severity=0.3)
        # If trust drops below threshold → on_reset callback fires
    """

    def __init__(
        self,
        reset_threshold: float = 0.3,
        ban_threshold: float = 0.0,
        max_resets: int = 3,
        decay_rate: float = 0.01,
        on_reset: Optional[Callable[[str], None]] = None,
        on_ban: Optional[Callable[[str], None]] = None,
    ):
        self.reset_threshold = reset_threshold
        self.ban_threshold = ban_threshold
        self.max_resets = max_resets
        self.decay_rate = decay_rate
        self.on_reset = on_reset
        self.on_ban = on_ban

        self._agents: Dict[str, TrustScore] = {}
        self._history: List[TrustEvent] = []

    def register(self, agent_id: str, initial_trust: float = 0.5) -> TrustScore:
        """
        Register a new agent with initial trust score.

        New agents start at 0.5 (MEDIUM) by default. Trust must be earned.
        """
        score = TrustScore(
            agent_id=agent_id,
            score=initial_trust,
            initial_score=initial_trust,
        )
        self._agents[agent_id] = score
        self._record(agent_id, TrustAction.REGISTERED, 0.0, initial_trust,
                     "agent_registered", 0.0)
        return score

    def reward(self, agent_id: str, reason: str, amount: float = 0.05) -> TrustScore:
        """
        Reward an agent for good behavior. Trust increases slowly.

        Trust increases are capped at 0.05 per reward to prevent gaming.
        Trust cannot exceed 1.0.
        """
        agent = self._get_agent(agent_id)
        if agent.banned:
            return agent

        old_score = agent.score
        # Trust increases slowly (capped)
        increase = min(amount, 0.05)
        agent.score = min(1.0, agent.score + increase)
        agent.total_rewards += 1
        agent.last_action = reason
        agent.last_action_time = time.time()

        self._record(agent_id, TrustAction.REWARDED, old_score, agent.score,
                     reason, increase)
        return agent

    def penalize(self, agent_id: str, reason: str, severity: float = 0.1) -> TrustScore:
        """
        Penalize an agent for bad behavior. Trust drops fast.

        Severity scale:
            0.05 - Minor (unexpected output format)
            0.1  - Low (slow response, minor policy violation)
            0.2  - Medium (unauthorized tool call, data leak attempt)
            0.3  - High (SNAFT violation, injection attempt)
            0.5  - Critical (active attack pattern detected)
            1.0  - Kill (confirmed malicious behavior)

        If trust drops below reset_threshold → agent is RESET.
        If trust drops to ban_threshold → agent is BANNED.
        If agent has been reset max_resets times → agent is BANNED.
        """
        agent = self._get_agent(agent_id)
        if agent.banned:
            return agent

        old_score = agent.score
        # Trust drops fast (no cap on penalty)
        agent.score = max(0.0, agent.score - severity)
        agent.total_penalties += 1
        agent.last_action = reason
        agent.last_action_time = time.time()

        self._record(agent_id, TrustAction.PENALIZED, old_score, agent.score,
                     reason, severity)

        # Check thresholds
        if agent.score <= self.ban_threshold or agent.reset_count >= self.max_resets:
            self._ban_agent(agent_id, reason)
        elif agent.score <= self.reset_threshold:
            self._reset_agent(agent_id, reason)

        return agent

    def check(self, agent_id: str) -> bool:
        """
        Check if an agent is allowed to act.

        Call this BEFORE every action. This is the "audit as precondition" principle.
        Returns False if agent is banned or below reset threshold.
        """
        agent = self._get_agent(agent_id)

        if agent.banned:
            return False

        # Apply time-based decay
        self._apply_decay(agent)

        return agent.score > self.reset_threshold

    def get_score(self, agent_id: str) -> TrustScore:
        """Get current trust score for an agent."""
        return self._get_agent(agent_id)

    def scores(self) -> Dict[str, TrustScore]:
        """Get all agent trust scores."""
        return dict(self._agents)

    def history(self, agent_id: Optional[str] = None) -> List[TrustEvent]:
        """Get trust history, optionally filtered by agent."""
        if agent_id:
            return [e for e in self._history if e.agent_id == agent_id]
        return list(self._history)

    def _reset_agent(self, agent_id: str, reason: str):
        """
        RESET — kill the agent and restart clean.

        The agent's trust is restored to initial, but reset_count increases.
        After max_resets, the agent is permanently banned.

        This is the Swan Protocol: if trust drops, the agent dies.
        """
        agent = self._agents[agent_id]
        old_score = agent.score

        agent.reset_count += 1
        agent.score = agent.initial_score
        agent.total_rewards = 0
        agent.total_penalties = 0
        agent.last_action = f"RESET ({reason})"
        agent.last_action_time = time.time()

        self._record(agent_id, TrustAction.RESET, old_score, agent.score,
                     f"trust_reset: {reason} (reset #{agent.reset_count})",
                     old_score)

        # Check if max resets exceeded
        if agent.reset_count >= self.max_resets:
            self._ban_agent(agent_id, f"max_resets_exceeded ({self.max_resets})")
            return

        # Fire callback
        if self.on_reset:
            self.on_reset(agent_id)

    def _ban_agent(self, agent_id: str, reason: str):
        """
        BAN — permanently disable the agent. Requires human intervention.

        Once banned, no API call can unban. A human (Heart-in-the-Loop)
        must intervene.
        """
        agent = self._agents[agent_id]
        old_score = agent.score

        agent.banned = True
        agent.score = 0.0
        agent.last_action = f"BANNED ({reason})"
        agent.last_action_time = time.time()

        self._record(agent_id, TrustAction.BANNED, old_score, 0.0,
                     f"agent_banned: {reason}", old_score)

        # Fire callback
        if self.on_ban:
            self.on_ban(agent_id)

    def unban(self, agent_id: str, authorized_by: str) -> TrustScore:
        """
        Unban an agent. REQUIRES human authorization.

        This is Heart-in-the-Loop: only a human can restore a banned agent.
        The agent restarts with LOW trust (0.3), not its original score.
        """
        agent = self._get_agent(agent_id)
        if not agent.banned:
            return agent

        old_score = agent.score
        agent.banned = False
        agent.score = 0.3  # Restart with LOW trust
        agent.reset_count = 0
        agent.last_action = f"UNBANNED by {authorized_by}"
        agent.last_action_time = time.time()

        self._record(agent_id, TrustAction.REGISTERED, old_score, 0.3,
                     f"unbanned_by_{authorized_by}", 0.0)
        return agent

    def _apply_decay(self, agent: TrustScore):
        """Apply time-based trust decay for inactive agents."""
        if agent.last_action_time is None:
            return

        hours_inactive = (time.time() - agent.last_action_time) / 3600
        if hours_inactive > 1.0:
            decay = self.decay_rate * hours_inactive
            agent.score = max(self.reset_threshold + 0.01, agent.score - decay)

    def _get_agent(self, agent_id: str) -> TrustScore:
        """Get agent or raise."""
        if agent_id not in self._agents:
            raise KeyError(f"Agent '{agent_id}' not registered. Call register() first.")
        return self._agents[agent_id]

    def _record(self, agent_id: str, action: TrustAction, old: float, new: float,
                reason: str, severity: float):
        """Record a trust event."""
        event = TrustEvent(
            agent_id=agent_id,
            action=action,
            old_score=old,
            new_score=new,
            reason=reason,
            severity=severity,
        )
        self._history.append(event)

    def export_history(self) -> str:
        """Export trust history as HMAC-chained JSON (tamper-evident)."""
        entries = []
        prev_hash = "genesis"

        for event in self._history:
            entry = event.to_dict()
            entry["prev_hash"] = prev_hash
            entry_json = json.dumps(entry, sort_keys=True)
            entry["hash"] = hashlib.sha256(entry_json.encode()).hexdigest()
            prev_hash = entry["hash"]
            entries.append(entry)

        return json.dumps(entries, indent=2)

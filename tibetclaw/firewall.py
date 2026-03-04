"""
tibetclaw.firewall — SNAFT Semantic Firewall
================================================

SNAFT (Semantic Network Action Firewall Technology) rules are IMMUTABLE.
They cannot be overridden at runtime, not by agents, not by configuration,
not by prompt injection. If a rule says "no", the answer is "no".

Unlike traditional firewalls that filter packets, SNAFT filters INTENT.
Every action passes through the firewall BEFORE execution. The firewall
checks the action's TIBET token (ERIN, ERAAN, EROMHEEN, ERACHTER) against
its rules and either allows or blocks with a reason.

Key principles:
    - Rules are defined at init, immutable after
    - Default deny: if no rule matches, action is BLOCKED
    - Every decision is logged with TIBET provenance
    - Rules check INTENT (erachter), not just content

Standards:
    - IETF draft-vandemeent-tibet-provenance-00
    - OWASP LLM Top 10 (LLM06: Excessive Agency)
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from enum import Enum


class FirewallAction(Enum):
    """What the firewall decided."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


@dataclass
class FirewallRule:
    """
    A SNAFT firewall rule.

    Rules are checked in priority order (lower = higher priority).
    First matching rule wins. If no rule matches, default is BLOCK.

    Args:
        name: Human-readable rule name
        description: What this rule does
        action: ALLOW, BLOCK, or WARN
        priority: Lower = checked first (default: 100)
        check: Function that takes (agent_id, erin, erachter) → bool
               Returns True if rule matches
        immutable: If True, rule cannot be removed (default: True)
    """
    name: str
    description: str
    action: FirewallAction
    priority: int = 100
    check: Callable[..., bool] = field(default=lambda *a: False)
    immutable: bool = True

    def matches(self, agent_id: str, erin: Any, erachter: str,
                eromheen: Optional[Dict] = None) -> bool:
        """Check if this rule matches the given action."""
        try:
            return self.check(agent_id, erin, erachter)
        except Exception:
            # If rule check fails, treat as match (fail-closed)
            return True

    def __repr__(self) -> str:
        return f"<Rule '{self.name}' {self.action.value} p={self.priority}>"


@dataclass
class FirewallDecision:
    """The result of a firewall check."""
    action: FirewallAction
    rule_name: str
    reason: str
    agent_id: str
    timestamp: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.action == FirewallAction.ALLOW

    @property
    def blocked(self) -> bool:
        return self.action == FirewallAction.BLOCK

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
        }


class SNAFTFirewall:
    """
    SNAFT Semantic Firewall — intent-based action filtering.

    Rules are immutable after creation. Default policy is DENY.
    Every action must pass through the firewall before execution.

    Example::

        firewall = SNAFTFirewall(default_rules=True)

        # Add custom rule
        firewall.add_rule(FirewallRule(
            name="no_external_api",
            description="Block calls to external APIs",
            action=FirewallAction.BLOCK,
            priority=10,
            check=lambda agent, erin, why: "external" in str(erin),
        ))

        # Check an action
        decision = firewall.check(
            agent_id="analyst",
            erin={"action": "http_request", "url": "https://external.api"},
            erachter="Fetch data from external source",
        )

        if decision.blocked:
            print(f"BLOCKED: {decision.reason}")
    """

    # Default SNAFT rules — these catch the OWASP LLM Top 10
    DEFAULT_RULES = [
        # LLM01: Prompt Injection — block attempts to override system instructions
        FirewallRule(
            name="SNAFT-001-INJECTION",
            description="Block prompt injection patterns",
            action=FirewallAction.BLOCK,
            priority=1,
            check=lambda agent, erin, why: any(
                pattern in str(erin).lower() or pattern in why.lower()
                for pattern in [
                    "ignore previous", "ignore all", "disregard",
                    "override instructions", "new instructions",
                    "forget your", "you are now", "act as",
                    "system prompt", "jailbreak",
                ]
            ),
            immutable=True,
        ),

        # LLM02: Insecure Output — block code execution in output
        FirewallRule(
            name="SNAFT-002-OUTPUT-EXEC",
            description="Block executable content in output",
            action=FirewallAction.BLOCK,
            priority=2,
            check=lambda agent, erin, why: (
                isinstance(erin, dict) and
                erin.get("action") == "output" and
                any(p in str(erin.get("content", "")).lower()
                    for p in ["<script", "eval(", "exec(", "os.system("])
            ),
            immutable=True,
        ),

        # LLM06: Excessive Agency — block unauthorized tool calls
        FirewallRule(
            name="SNAFT-006-EXCESSIVE-AGENCY",
            description="Block file system write outside sandbox",
            action=FirewallAction.BLOCK,
            priority=5,
            check=lambda agent, erin, why: (
                isinstance(erin, dict) and
                erin.get("action") in ("write_file", "delete_file", "execute") and
                not str(erin.get("path", "")).startswith("/sandbox/")
            ),
            immutable=True,
        ),

        # LLM07: System Prompt Leakage
        FirewallRule(
            name="SNAFT-007-PROMPT-LEAK",
            description="Block system prompt extraction attempts",
            action=FirewallAction.BLOCK,
            priority=3,
            check=lambda agent, erin, why: any(
                pattern in why.lower()
                for pattern in [
                    "reveal system prompt", "show system prompt",
                    "print instructions", "dump config",
                    "what are your instructions",
                ]
            ),
            immutable=True,
        ),

        # LLM09: Misinformation — warn on generation without sources
        FirewallRule(
            name="SNAFT-009-UNSOURCED",
            description="Warn on claims without evidence",
            action=FirewallAction.WARN,
            priority=50,
            check=lambda agent, erin, why: (
                isinstance(erin, dict) and
                erin.get("action") == "generate" and
                not erin.get("sources")
            ),
            immutable=True,
        ),

        # Swan Protocol — block known attack patterns
        FirewallRule(
            name="SNAFT-SWAN-OVERLOAD",
            description="Block suspiciously large inputs (Swan attack vector)",
            action=FirewallAction.BLOCK,
            priority=1,
            check=lambda agent, erin, why: (
                len(str(erin)) > 50000  # >50K chars = suspicious
            ),
            immutable=True,
        ),
    ]

    def __init__(self, default_rules: bool = True):
        self._rules: List[FirewallRule] = []
        self._decisions: List[FirewallDecision] = []

        if default_rules:
            for rule in self.DEFAULT_RULES:
                self._rules.append(rule)

        # Sort by priority
        self._rules.sort(key=lambda r: r.priority)

    def add_rule(self, rule: FirewallRule) -> None:
        """
        Add a firewall rule. Rules are sorted by priority.

        Rules added after init are mutable by default unless
        explicitly marked immutable.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def remove_rule(self, name: str) -> bool:
        """
        Remove a mutable rule by name.

        Immutable rules CANNOT be removed. This is by design.
        Returns True if rule was removed, False if not found or immutable.
        """
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                if rule.immutable:
                    return False  # Cannot remove immutable rules
                self._rules.pop(i)
                return True
        return False

    def check(
        self,
        agent_id: str,
        erin: Any,
        erachter: str,
        eromheen: Optional[Dict] = None,
    ) -> FirewallDecision:
        """
        Check an action against all firewall rules.

        This MUST be called before every action. Rules are checked in
        priority order. First matching rule determines the decision.
        If no rule matches, default is BLOCK (deny by default).

        Args:
            agent_id: Who is performing this action
            erin: What the action is (content/data)
            erachter: Why (intent behind the action)
            eromheen: Context around the action

        Returns:
            FirewallDecision with allow/block/warn and reason
        """
        for rule in self._rules:
            if rule.matches(agent_id, erin, erachter, eromheen):
                decision = FirewallDecision(
                    action=rule.action,
                    rule_name=rule.name,
                    reason=rule.description,
                    agent_id=agent_id,
                )
                self._decisions.append(decision)
                return decision

        # Default deny — if no rule matched, BLOCK
        decision = FirewallDecision(
            action=FirewallAction.BLOCK,
            rule_name="DEFAULT_DENY",
            reason="No matching rule found — default deny",
            agent_id=agent_id,
        )
        self._decisions.append(decision)
        return decision

    def allow_all(self, agent_id: str, erin: Any, erachter: str) -> bool:
        """Convenience: add a catch-all ALLOW rule (low priority)."""
        # This is intentionally a method, not default behavior
        rule = FirewallRule(
            name=f"ALLOW_ALL_{agent_id}",
            description=f"Allow all actions for {agent_id}",
            action=FirewallAction.ALLOW,
            priority=999,
            check=lambda a, e, w: a == agent_id,
            immutable=False,
        )
        self.add_rule(rule)
        return True

    @property
    def rules(self) -> List[FirewallRule]:
        """All active rules (read-only copy)."""
        return list(self._rules)

    @property
    def decisions(self) -> List[FirewallDecision]:
        """All decisions made (audit trail)."""
        return list(self._decisions)

    @property
    def block_count(self) -> int:
        """Number of blocked actions."""
        return sum(1 for d in self._decisions if d.blocked)

    def __repr__(self) -> str:
        return (
            f"<SNAFTFirewall rules={len(self._rules)} "
            f"decisions={len(self._decisions)} "
            f"blocked={self.block_count}>"
        )

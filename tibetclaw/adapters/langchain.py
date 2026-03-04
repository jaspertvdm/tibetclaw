"""
tibetclaw.adapters.langchain — LangChain + TIBET Integration
================================================================

Wraps any LangChain chain/agent with TibetClaw's trust kernel,
provenance chain, and SNAFT firewall. Zero code changes required.

Usage::

    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from tibetclaw.adapters.langchain import TibetChain

    # Your existing LangChain chain
    prompt = ChatPromptTemplate.from_template("Analyze: {input}")
    llm = ChatOpenAI(model="gpt-4")
    chain = prompt | llm

    # Wrap with TibetClaw — one line
    tibet_chain = TibetChain(chain, agent_id="analyst")

    # Every invoke now has trust gating + provenance + firewall
    result = tibet_chain.invoke({"input": "quarterly report"})

    # Full audit trail
    print(result.tibet_token)
    print(result.trust_score)

What TibetChain adds:
    1. Trust check BEFORE every invoke (FIR/A behavioral trust)
    2. Firewall check on input AND output (SNAFT semantic filtering)
    3. TIBET provenance token for every execution
    4. Automatic trust reward/penalty based on outcome
    5. Swan Protocol: agent reset on trust violation

Requirements:
    pip install tibetclaw[langchain]
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..trust import TrustKernel, TrustScore
from ..provenance import ProvenanceChain
from ..firewall import SNAFTFirewall, FirewallAction
from ..orchestrator import TaskResult, TaskStatus

try:
    from langchain_core.runnables import Runnable, RunnableConfig
    from langchain_core.callbacks import BaseCallbackHandler

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    Runnable = object
    RunnableConfig = dict
    BaseCallbackHandler = object


class TibetChain:
    """
    Wraps a LangChain Runnable with TIBET trust, provenance, and firewall.

    This is a drop-in replacement. Your existing chain works unchanged,
    but every invocation now goes through:

        Trust Gate → Firewall → Execute → Provenance → Trust Update

    Args:
        chain: Any LangChain Runnable (chain, agent, tool, etc.)
        agent_id: Identifier for trust tracking (default: "langchain")
        trust_kernel: Custom TrustKernel (or creates default)
        firewall: Custom SNAFTFirewall (or creates default)
        provenance: Custom ProvenanceChain (or creates default)
        intent: Default intent/purpose for provenance (ERACHTER)

    Example::

        tibet_chain = TibetChain(
            chain=my_langchain_chain,
            agent_id="analyst",
            intent="Analyze financial documents for compliance",
        )

        result = tibet_chain.invoke({"input": "Q4 report"})
        assert result.success
        print(result.output)
        print(result.tibet_chain)
    """

    def __init__(
        self,
        chain: Any,
        agent_id: str = "langchain",
        trust_kernel: Optional[TrustKernel] = None,
        firewall: Optional[SNAFTFirewall] = None,
        provenance: Optional[ProvenanceChain] = None,
        intent: str = "",
    ):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain is not installed. Install with: pip install tibetclaw[langchain]"
            )

        self.chain = chain
        self.agent_id = agent_id
        self.intent = intent

        self.trust = trust_kernel or TrustKernel()
        self.firewall = firewall or SNAFTFirewall(default_rules=True)
        self.provenance = provenance or ProvenanceChain()

        # Register agent with trust kernel
        if agent_id not in self.trust.scores():
            self.trust.register(agent_id)

        # Add a permissive rule for normal LangChain operations
        from ..firewall import FirewallRule
        self.firewall.add_rule(FirewallRule(
            name="LANGCHAIN_ALLOW_NORMAL",
            description="Allow standard LangChain operations",
            action=FirewallAction.ALLOW,
            priority=500,
            check=lambda a, e, w: a == agent_id,
            immutable=False,
        ))

    def invoke(
        self,
        input: Any,
        config: Optional[Any] = None,
        intent: Optional[str] = None,
        **kwargs,
    ) -> TaskResult:
        """
        Invoke the wrapped chain with full TIBET pipeline.

        Same interface as LangChain's invoke(), but returns a TaskResult
        with provenance, trust score, and firewall decision.

        Args:
            input: The input to the chain (same as LangChain)
            config: Optional RunnableConfig
            intent: Override the default intent for this call
            **kwargs: Passed through to the chain

        Returns:
            TaskResult with output, TIBET token, trust score
        """
        start_time = time.time()
        call_intent = intent or self.intent or "LangChain invoke"

        # --- Trust Gate ---
        if not self.trust.check(self.agent_id):
            score = self.trust.get_score(self.agent_id)
            token = self.provenance.record(
                agent_id=self.agent_id,
                erin={"action": "blocked", "input": str(input)[:200]},
                erachter=call_intent,
            )
            return TaskResult(
                status=TaskStatus.UNTRUSTED,
                error=f"Trust too low: {score.score:.2f} ({score.band})",
                agent_id=self.agent_id,
                tibet_token=token,
                trust_score=score,
                duration=time.time() - start_time,
            )

        # --- Firewall Gate (input) ---
        fw_decision = self.firewall.check(
            agent_id=self.agent_id,
            erin=input,
            erachter=call_intent,
        )

        if fw_decision.blocked:
            self.trust.penalize(self.agent_id, reason=f"input_blocked: {fw_decision.rule_name}",
                                severity=0.1)
            token = self.provenance.record(
                agent_id=self.agent_id,
                erin={"action": "firewall_blocked", "input": str(input)[:200]},
                erachter=call_intent,
            )
            return TaskResult(
                status=TaskStatus.BLOCKED,
                error=f"Input blocked by {fw_decision.rule_name}",
                agent_id=self.agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(self.agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )

        # --- Execute Chain ---
        try:
            output = self.chain.invoke(input, config=config, **kwargs)

            # --- Firewall Gate (output) ---
            output_check = self.firewall.check(
                agent_id=self.agent_id,
                erin={"action": "output", "content": str(output)[:1000]},
                erachter=f"Output from: {call_intent}",
            )

            if output_check.blocked:
                self.trust.penalize(self.agent_id, reason=f"output_blocked: {output_check.rule_name}",
                                    severity=0.15)
                token = self.provenance.record(
                    agent_id=self.agent_id,
                    erin={"action": "output_blocked", "input": str(input)[:200]},
                    erachter=call_intent,
                )
                return TaskResult(
                    status=TaskStatus.BLOCKED,
                    error=f"Output blocked by {output_check.rule_name}",
                    agent_id=self.agent_id,
                    tibet_token=token,
                    trust_score=self.trust.get_score(self.agent_id),
                    firewall_decision=output_check,
                    duration=time.time() - start_time,
                )

            # --- Success: Record Provenance + Reward ---
            token = self.provenance.record(
                agent_id=self.agent_id,
                erin={
                    "action": "langchain_invoke",
                    "input": str(input)[:200],
                    "output": str(output)[:200],
                },
                eraan=[f"chain:{type(self.chain).__name__}"],
                eromheen={"framework": "langchain"},
                erachter=call_intent,
            )
            self.trust.reward(self.agent_id, reason="invoke_success", amount=0.02)

            return TaskResult(
                status=TaskStatus.SUCCESS,
                output=output,
                agent_id=self.agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(self.agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )

        except Exception as e:
            # --- Error: Record + Penalize ---
            token = self.provenance.record(
                agent_id=self.agent_id,
                erin={"action": "error", "input": str(input)[:200], "error": str(e)},
                erachter=call_intent,
            )
            self.trust.penalize(self.agent_id, reason=f"invoke_error: {str(e)[:100]}",
                                severity=0.05)

            return TaskResult(
                status=TaskStatus.ERROR,
                error=str(e),
                agent_id=self.agent_id,
                tibet_token=token,
                trust_score=self.trust.get_score(self.agent_id),
                firewall_decision=fw_decision,
                duration=time.time() - start_time,
            )

    async def ainvoke(self, input: Any, config: Optional[Any] = None, **kwargs) -> TaskResult:
        """Async version of invoke. Same trust pipeline."""
        # For now, delegate to sync invoke
        # TODO: True async with achain.ainvoke
        return self.invoke(input, config=config, **kwargs)

    def __repr__(self) -> str:
        score = self.trust.get_score(self.agent_id)
        return (
            f"<TibetChain agent='{self.agent_id}' "
            f"trust={score.score:.2f} ({score.band}) "
            f"chain={type(self.chain).__name__}>"
        )


class TibetCallback(BaseCallbackHandler if LANGCHAIN_AVAILABLE else object):
    """
    LangChain callback handler that records TIBET provenance tokens
    for every LLM call, tool use, and chain step.

    Use this when you want provenance without wrapping your chain::

        from tibetclaw.adapters.langchain import TibetCallback

        callback = TibetCallback(agent_id="my-agent")

        # Add to any LangChain call
        chain.invoke(input, config={"callbacks": [callback]})

        # Get provenance
        print(callback.provenance.export())
    """

    def __init__(self, agent_id: str = "langchain",
                 provenance: Optional[ProvenanceChain] = None):
        if LANGCHAIN_AVAILABLE:
            super().__init__()
        self.agent_id = agent_id
        self.provenance = provenance or ProvenanceChain()

    def on_llm_start(self, serialized: Dict, prompts: List[str], **kwargs):
        self.provenance.record(
            agent_id=self.agent_id,
            erin={"action": "llm_start", "model": serialized.get("id", ["unknown"])},
            eraan=[f"prompt_count:{len(prompts)}"],
            erachter="LLM inference started",
        )

    def on_llm_end(self, response, **kwargs):
        self.provenance.record(
            agent_id=self.agent_id,
            erin={"action": "llm_end", "generations": len(getattr(response, 'generations', []))},
            erachter="LLM inference completed",
        )

    def on_tool_start(self, serialized: Dict, input_str: str, **kwargs):
        self.provenance.record(
            agent_id=self.agent_id,
            erin={"action": "tool_start", "tool": serialized.get("name", "unknown"),
                  "input": input_str[:200]},
            erachter="Tool execution started",
        )

    def on_tool_end(self, output: str, **kwargs):
        self.provenance.record(
            agent_id=self.agent_id,
            erin={"action": "tool_end", "output": str(output)[:200]},
            erachter="Tool execution completed",
        )

    def on_chain_error(self, error: Exception, **kwargs):
        self.provenance.record(
            agent_id=self.agent_id,
            erin={"action": "chain_error", "error": str(error)[:200]},
            erachter="Chain execution failed",
        )

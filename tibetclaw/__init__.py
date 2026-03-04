"""
TibetClaw — Trust-First Agent Framework
=========================================

The trust kernel that agentic AI is missing.

While OpenClaw proved the market (250K+ stars) and Network-AI added orchestration,
neither provides behavioral trust, cryptographic provenance, or semantic firewalling.
TibetClaw does.

Core principles:
    1. Audit is a PRECONDITION, not an observation
    2. Trust is EARNED through behavior (FIR/A), not assigned by config
    3. Every action generates a cryptographic TIBET token
    4. SNAFT firewall rules are IMMUTABLE — not overridable at runtime
    5. Identity is INTENT-based (JIS), not credential-based

Quick start::

    from tibetclaw import Orchestrator

    orch = Orchestrator()
    orch.register("analyst", handler=my_analysis_fn)
    result = orch.run("Analyze this dataset")

    # Every action has a TIBET provenance token
    print(result.tibet_chain)
    # Trust is tracked per agent
    print(orch.trust_scores())

With LangChain::

    from tibetclaw.adapters.langchain import TibetChain

    chain = TibetChain(my_langchain_chain)
    result = chain.invoke({"input": "query"})
    # Full provenance, trust gating, SNAFT firewall — automatic

Standards:
    - IETF draft-vandemeent-tibet-provenance-00
    - IETF draft-vandemeent-jis-identity-00
    - Security-informed design (OWASP LLM Top 10 awareness)

One love, one fAmIly.
"""

__version__ = "0.3.1"
__author__ = "Jasper van de Meent & Root AI"
__email__ = "team@humotica.com"

from .orchestrator import Orchestrator, AgentConfig, TaskResult
from .trust import TrustKernel, TrustScore
from .provenance import ProvenanceChain
from .firewall import SNAFTFirewall, FirewallRule

__all__ = [
    "Orchestrator",
    "AgentConfig",
    "TaskResult",
    "TrustKernel",
    "TrustScore",
    "ProvenanceChain",
    "SNAFTFirewall",
    "FirewallRule",
]

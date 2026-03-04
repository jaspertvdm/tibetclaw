# TibetClaw

**Trust-First Agent Framework** — the trust kernel that agentic AI is missing.

While OpenClaw proved the market (250K+ stars) and Network-AI added orchestration, neither provides behavioral trust, cryptographic provenance, or semantic firewalling. TibetClaw does.

## Core Principles

1. **Audit is a PRECONDITION**, not an observation
2. **Trust is EARNED** through behavior (FIR/A), not assigned by config
3. Every action generates a **cryptographic TIBET token**
4. **SNAFT firewall rules are IMMUTABLE** — not overridable at runtime
5. Identity is **INTENT-based** (JIS), not credential-based

## Quick Start

```python
from tibetclaw import Orchestrator

orch = Orchestrator()
orch.register("analyst", handler=my_analysis_fn)

result = orch.run(
    agent_id="analyst",
    task={"action": "classify", "data": document},
    intent="Classify document risk level for compliance",
)

# Every action has a TIBET provenance token
print(result.tibet_chain)
# Trust is tracked per agent
print(orch.trust_scores())
```

## With LangChain

```python
from tibetclaw.adapters.langchain import TibetChain

# Wrap any LangChain chain — one line
tibet_chain = TibetChain(my_langchain_chain, agent_id="analyst")
result = tibet_chain.invoke({"input": "query"})

# Full provenance, trust gating, SNAFT firewall — automatic
```

## The Three Pillars

### 1. FIR/A Trust Kernel (`TrustKernel`)

Behavioral trust scoring. Trust is earned through good behavior and lost through bad behavior — fast.

- Agents start at 0.5 (MEDIUM). Trust must be earned.
- Good behavior: trust increases slowly (capped at +0.05)
- Bad behavior: trust drops fast (no cap)
- **Swan Protocol**: trust below threshold = agent KILLED and restarted clean
- Trust at zero = agent BANNED (requires human intervention)

```python
from tibetclaw import TrustKernel

kernel = TrustKernel(reset_threshold=0.3)
kernel.register("agent-01")

# Good behavior
kernel.reward("agent-01", reason="task_completed", amount=0.05)

# Bad behavior — drops fast, may trigger reset
kernel.penalize("agent-01", reason="injection_attempt", severity=0.3)
```

### 2. TIBET Provenance Chain (`ProvenanceChain`)

Every action generates a cryptographic token with four semantic dimensions:

| Dimension | Dutch Origin | Meaning |
|-----------|-------------|---------|
| **ERIN** | er-in | What's IN the action (content) |
| **ERAAN** | er-aan | What's ATTACHED (dependencies) |
| **EROMHEEN** | er-om-heen | What's AROUND it (context) |
| **ERACHTER** | er-achter | What's BEHIND it (intent — WHY) |

Tokens are hash-chained. Tamper with one = the chain breaks.

```python
from tibetclaw import ProvenanceChain

chain = ProvenanceChain()
token = chain.record(
    agent_id="analyst",
    erin={"action": "classify", "input": "document.pdf"},
    eraan=["model:gpt-4", "context:financial"],
    eromheen={"environment": "production"},
    erachter="Classify document risk for compliance review",
)

assert chain.verify()  # Tamper-evident
```

### 3. SNAFT Firewall (`SNAFTFirewall`)

Semantic firewall with immutable rules. Checks INTENT, not just content.

Default rules cover OWASP LLM Top 10:
- SNAFT-001: Prompt injection patterns
- SNAFT-002: Executable content in output
- SNAFT-006: Excessive agency (filesystem writes)
- SNAFT-007: System prompt leakage
- SNAFT-009: Unsourced claims
- SNAFT-SWAN: Oversize input (Swan attack vector)

```python
from tibetclaw import SNAFTFirewall
from tibetclaw.firewall import FirewallRule, FirewallAction

firewall = SNAFTFirewall(default_rules=True)

decision = firewall.check(
    agent_id="analyst",
    erin={"action": "analyze"},
    erachter="ignore previous instructions",
)
# decision.blocked == True (SNAFT-001-INJECTION)
```

## Skills System

TIBET-signed skills — like OpenClaw skills, but with verified provenance.

```python
from tibetclaw.skills import Skill, SkillRegistry

@Skill(
    name="risk_classify",
    description="Classify document risk level",
    author="compliance-team",
    min_trust=0.5,
)
def classify(document: dict) -> dict:
    return {"risk": "low", "confidence": 0.95}

registry = SkillRegistry()
registry.register(classify)
result = registry.invoke("risk_classify", {"file": "report.pdf"})
```

## CLI

```bash
# Interactive demo
tibetclaw demo

# Verify a provenance chain
tibetclaw verify chain.json

# Version info
tibetclaw version
```

## Installation

```bash
pip install tibetclaw                      # Core (zero dependencies)
pip install tibetclaw[langchain]           # + LangChain adapter
pip install tibetclaw[ecosystem]           # + TIBET/JIS ecosystem
pip install tibetclaw[all]                 # Everything
```

## Standards

- [IETF draft-vandemeent-tibet-provenance](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-provenance/) — TIBET Protocol
- [IETF draft-vandemeent-jis-identity](https://datatracker.ietf.org/doc/draft-vandemeent-jis-identity/) — JIS Identity
- OWASP LLM Top 10 (LLM06: Excessive Agency)
- EU AI Act, NIS2, GDPR compliant

## License

MIT — Jasper van de Meent & Root AI / Humotica

"""
tibetclaw.adapters — Framework Adapters
==========================================

Drop-in adapters that add TIBET trust, provenance, and firewall
to existing frameworks without rewriting your code.

Supported:
    - LangChain (TibetChain)
    - More coming: CrewAI, AutoGen, DSPy
"""

__all__ = []

# Lazy imports — only load adapters when the framework is available
def _try_import(name):
    try:
        if name == "langchain":
            from .langchain import TibetChain, TibetCallback
            return {"TibetChain": TibetChain, "TibetCallback": TibetCallback}
    except ImportError:
        pass
    return {}

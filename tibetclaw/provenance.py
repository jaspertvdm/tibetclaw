"""
tibetclaw.provenance — TIBET Provenance Chain
===============================================

Every action in TibetClaw generates a cryptographic TIBET token with
four semantic dimensions:

    ERIN      — What's in it (the action/content)
    ERAAN     — What's attached (dependencies, references)
    EROMHEEN  — What's around it (context, environment)
    ERACHTER  — What's behind it (intent — WHY this action)

Tokens are chained: each token references its parent's hash.
Break the chain = detected. Tamper with a token = detected.

Standards:
    - IETF draft-vandemeent-tibet-provenance-00
"""

import time
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TIBETToken:
    """A single TIBET provenance token."""
    token_id: str
    parent_id: Optional[str]
    agent_id: str
    timestamp: float
    erin: Any              # WHAT happened
    eraan: List[str]       # WHAT was attached (dependencies)
    eromheen: Dict         # CONTEXT around it
    erachter: str          # WHY (intent)
    token_hash: str = ""
    chain_index: int = 0

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "parent_id": self.parent_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "erin": self.erin,
            "eraan": self.eraan,
            "eromheen": self.eromheen,
            "erachter": self.erachter,
            "token_hash": self.token_hash,
            "chain_index": self.chain_index,
        }

    def __repr__(self) -> str:
        return f"<TIBETToken {self.token_id[:8]} agent={self.agent_id} idx={self.chain_index}>"


class ProvenanceChain:
    """
    TIBET Provenance Chain — tamper-evident chain of action tokens.

    Every action creates a token. Tokens are chained by hash reference.
    The chain is verifiable: if any token is modified or removed, the
    chain integrity check fails.

    Example::

        chain = ProvenanceChain()

        # Record an action
        token = chain.record(
            agent_id="analyst",
            erin={"action": "classify", "input": "document.pdf"},
            eraan=["model:gpt-4", "context:financial"],
            eromheen={"environment": "production", "user": "jasper"},
            erachter="Classify document risk level for compliance review",
        )

        # Verify chain integrity
        assert chain.verify()

        # Get full chain for audit
        for t in chain.tokens:
            print(f"{t.chain_index}: {t.erachter}")
    """

    def __init__(self):
        self._tokens: List[TIBETToken] = []
        self._genesis_hash = self._compute_hash("TIBET_GENESIS_BLOCK")

    def record(
        self,
        agent_id: str,
        erin: Any,
        eraan: Optional[List[str]] = None,
        eromheen: Optional[Dict] = None,
        erachter: str = "",
    ) -> TIBETToken:
        """
        Record an action in the provenance chain.

        Args:
            agent_id: Who performed this action
            erin: What happened (content/action data)
            eraan: What was attached (dependencies, model refs)
            eromheen: Context (environment, state, user)
            erachter: Why — the intent behind this action

        Returns:
            The created TIBETToken
        """
        parent_id = self._tokens[-1].token_id if self._tokens else None
        parent_hash = self._tokens[-1].token_hash if self._tokens else self._genesis_hash

        token = TIBETToken(
            token_id=str(uuid.uuid4()),
            parent_id=parent_id,
            agent_id=agent_id,
            timestamp=time.time(),
            erin=erin,
            eraan=eraan or [],
            eromheen=eromheen or {},
            erachter=erachter,
            chain_index=len(self._tokens),
        )

        # Compute hash including parent hash (chain integrity)
        hash_input = json.dumps({
            "parent_hash": parent_hash,
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "timestamp": token.timestamp,
            "erin": str(token.erin),
            "eraan": token.eraan,
            "eromheen": token.eromheen,
            "erachter": token.erachter,
        }, sort_keys=True)
        token.token_hash = self._compute_hash(hash_input)

        self._tokens.append(token)
        return token

    def verify(self) -> bool:
        """
        Verify the entire chain is intact.

        Checks that every token's hash correctly references its parent.
        If any token has been tampered with or removed, this returns False.
        """
        if not self._tokens:
            return True

        prev_hash = self._genesis_hash

        for token in self._tokens:
            expected_hash = self._compute_hash(json.dumps({
                "parent_hash": prev_hash,
                "token_id": token.token_id,
                "agent_id": token.agent_id,
                "timestamp": token.timestamp,
                "erin": str(token.erin),
                "eraan": token.eraan,
                "eromheen": token.eromheen,
                "erachter": token.erachter,
            }, sort_keys=True))

            if token.token_hash != expected_hash:
                return False

            prev_hash = token.token_hash

        return True

    @property
    def tokens(self) -> List[TIBETToken]:
        """All tokens in the chain."""
        return list(self._tokens)

    @property
    def length(self) -> int:
        """Number of tokens in the chain."""
        return len(self._tokens)

    @property
    def last_token(self) -> Optional[TIBETToken]:
        """Most recent token."""
        return self._tokens[-1] if self._tokens else None

    def agent_tokens(self, agent_id: str) -> List[TIBETToken]:
        """Get all tokens for a specific agent."""
        return [t for t in self._tokens if t.agent_id == agent_id]

    def export(self) -> str:
        """Export chain as JSON."""
        return json.dumps([t.to_dict() for t in self._tokens], indent=2)

    def _compute_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def __len__(self) -> int:
        return len(self._tokens)

    def __repr__(self) -> str:
        return f"<ProvenanceChain tokens={len(self._tokens)} verified={self.verify()}>"

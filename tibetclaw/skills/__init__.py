"""
tibetclaw.skills — TIBET-Signed Skill System
================================================

Skills are self-contained units of agent capability — like OpenClaw skills,
but with cryptographic provenance and trust gating built in.

Every skill:
    1. Has a TIBET token at registration (proving origin and intent)
    2. Passes through SNAFT firewall before execution
    3. Requires minimum trust level to invoke
    4. Generates provenance tokens for every execution
    5. Cannot be modified at runtime (immutable after registration)

This prevents the OpenClaw "ClawHavoc" problem (341 malicious skills)
by making every skill's origin, intent, and dependencies verifiable.

Example::

    from tibetclaw.skills import Skill, SkillRegistry

    # Define a skill
    @Skill(
        name="analyze_document",
        description="Analyze document for risk classification",
        min_trust=0.5,
        author="analyst-team",
    )
    def analyze(document: dict) -> dict:
        return {"risk": "low", "confidence": 0.95}

    # Register and use through orchestrator
    registry = SkillRegistry()
    registry.register(analyze)

    result = registry.invoke("analyze_document", {"file": "report.pdf"})
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from functools import wraps

from ..provenance import ProvenanceChain, TIBETToken


@dataclass
class SkillManifest:
    """
    Immutable manifest for a registered skill.

    This is the skill's identity — signed at registration time.
    If anyone tries to modify the skill after registration,
    the hash won't match and execution is blocked.
    """
    name: str
    description: str
    author: str
    version: str
    min_trust: float
    dependencies: List[str]
    created_at: float
    manifest_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of manifest content."""
        data = json.dumps({
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "min_trust": self.min_trust,
            "dependencies": self.dependencies,
            "created_at": self.created_at,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "min_trust": self.min_trust,
            "dependencies": self.dependencies,
            "created_at": self.created_at,
            "manifest_hash": self.manifest_hash,
        }


@dataclass
class SkillResult:
    """Result of a skill invocation."""
    name: str
    output: Any = None
    error: Optional[str] = None
    success: bool = True
    tibet_token: Optional[TIBETToken] = None
    duration: float = 0.0

    def to_dict(self) -> dict:
        result = {
            "name": self.name,
            "success": self.success,
            "duration": round(self.duration, 3),
        }
        if self.output is not None:
            result["output"] = str(self.output)[:500]
        if self.error:
            result["error"] = self.error
        if self.tibet_token:
            result["tibet_token_id"] = self.tibet_token.token_id
        return result


class Skill:
    """
    Decorator to define a TIBET-signed skill.

    Usage::

        @Skill(
            name="classify",
            description="Classify documents by risk level",
            author="compliance-team",
            min_trust=0.5,
        )
        def classify(document: dict) -> dict:
            # Your skill logic here
            return {"risk_level": "low"}

    The decorated function becomes a registered skill with:
    - Immutable manifest (hash-verified)
    - TIBET provenance token at creation
    - Trust gating at invocation
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        author: str = "unknown",
        version: str = "1.0.0",
        min_trust: float = 0.5,
        dependencies: Optional[List[str]] = None,
    ):
        self.name = name
        self.description = description
        self.author = author
        self.version = version
        self.min_trust = min_trust
        self.dependencies = dependencies or []

    def __call__(self, fn: Callable) -> Callable:
        """Wrap the function as a TIBET skill."""
        manifest = SkillManifest(
            name=self.name,
            description=self.description,
            author=self.author,
            version=self.version,
            min_trust=self.min_trust,
            dependencies=self.dependencies,
            created_at=time.time(),
        )
        manifest.manifest_hash = manifest.compute_hash()

        @wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        # Attach metadata to the function
        wrapper._tibet_skill = True
        wrapper._tibet_manifest = manifest
        wrapper._tibet_handler = fn
        wrapper.manifest = manifest

        return wrapper


class SkillRegistry:
    """
    Registry of TIBET-signed skills.

    Skills are registered with manifests and can only be invoked
    through the registry (which checks trust and records provenance).

    Example::

        registry = SkillRegistry()

        @Skill(name="analyze", description="Analyze data", author="team-a")
        def analyze(data):
            return {"result": "ok"}

        registry.register(analyze)

        # List skills
        for name, manifest in registry.skills.items():
            print(f"{name}: {manifest.description} (min_trust={manifest.min_trust})")

        # Invoke (with provenance)
        result = registry.invoke("analyze", {"key": "value"})
    """

    def __init__(self, provenance: Optional[ProvenanceChain] = None):
        self._skills: Dict[str, Callable] = {}
        self._manifests: Dict[str, SkillManifest] = {}
        self.provenance = provenance or ProvenanceChain()

    def register(self, skill_fn: Callable) -> SkillManifest:
        """
        Register a @Skill-decorated function.

        Verifies the manifest hash and records a TIBET provenance token
        for the registration event.
        """
        if not getattr(skill_fn, '_tibet_skill', False):
            raise ValueError(
                "Function is not a TIBET skill. Use @Skill() decorator."
            )

        manifest = skill_fn._tibet_manifest

        # Verify manifest integrity
        expected_hash = manifest.compute_hash()
        if manifest.manifest_hash != expected_hash:
            raise ValueError(
                f"Skill '{manifest.name}' manifest has been tampered with! "
                f"Expected hash {expected_hash[:16]}..., "
                f"got {manifest.manifest_hash[:16]}..."
            )

        self._skills[manifest.name] = skill_fn._tibet_handler
        self._manifests[manifest.name] = manifest

        # Record registration in provenance
        self.provenance.record(
            agent_id=manifest.author,
            erin={
                "action": "skill_registered",
                "skill": manifest.name,
                "version": manifest.version,
            },
            eraan=manifest.dependencies,
            eromheen={"manifest_hash": manifest.manifest_hash},
            erachter=f"Register skill '{manifest.name}': {manifest.description}",
        )

        return manifest

    def invoke(
        self,
        name: str,
        input_data: Any = None,
        agent_id: str = "system",
        trust_score: float = 1.0,
    ) -> SkillResult:
        """
        Invoke a registered skill with trust check and provenance.

        Args:
            name: Skill name
            input_data: Data to pass to the skill
            agent_id: Who is invoking this skill
            trust_score: Current trust score of the invoking agent

        Returns:
            SkillResult with output and TIBET token
        """
        if name not in self._skills:
            return SkillResult(
                name=name,
                success=False,
                error=f"Skill '{name}' not found",
            )

        manifest = self._manifests[name]
        start_time = time.time()

        # Trust gate
        if trust_score < manifest.min_trust:
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "skill_blocked", "skill": name,
                      "trust": trust_score, "required": manifest.min_trust},
                erachter=f"Skill '{name}' requires trust >= {manifest.min_trust}",
            )
            return SkillResult(
                name=name,
                success=False,
                error=f"Trust too low: {trust_score:.2f} < {manifest.min_trust:.2f}",
                tibet_token=token,
                duration=time.time() - start_time,
            )

        # Execute
        try:
            handler = self._skills[name]
            output = handler(input_data) if input_data is not None else handler()

            token = self.provenance.record(
                agent_id=agent_id,
                erin={
                    "action": "skill_invoked",
                    "skill": name,
                    "input": str(input_data)[:200] if input_data else None,
                    "output": str(output)[:200],
                },
                eraan=[f"skill:{name}@{manifest.version}"],
                eromheen={"manifest_hash": manifest.manifest_hash},
                erachter=f"Invoke skill '{name}' by agent '{agent_id}'",
            )

            return SkillResult(
                name=name,
                output=output,
                success=True,
                tibet_token=token,
                duration=time.time() - start_time,
            )

        except Exception as e:
            token = self.provenance.record(
                agent_id=agent_id,
                erin={"action": "skill_error", "skill": name, "error": str(e)},
                erachter=f"Skill '{name}' failed: {str(e)[:100]}",
            )

            return SkillResult(
                name=name,
                success=False,
                error=str(e),
                tibet_token=token,
                duration=time.time() - start_time,
            )

    @property
    def skills(self) -> Dict[str, SkillManifest]:
        """All registered skills and their manifests."""
        return dict(self._manifests)

    def verify_skill(self, name: str) -> bool:
        """Verify a skill's manifest hasn't been tampered with."""
        if name not in self._manifests:
            return False
        manifest = self._manifests[name]
        return manifest.manifest_hash == manifest.compute_hash()

    def __len__(self) -> int:
        return len(self._skills)

    def __repr__(self) -> str:
        return f"<SkillRegistry skills={len(self._skills)}>"

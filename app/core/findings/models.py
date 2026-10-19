import uuid

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional, Literal


def make_finding_id(*parts: Any) -> str:
    """
    Create a deterministic finding identifier derived from finding
    identity. This keeps repeated rule evaluation reproducible.
    """
    normalized = "::".join(
        "" if part is None else str(part).strip() for part in parts
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, normalized or "digital-footprint-finding"))


def make_identity_key(rule_id: Any, finding_type: Any, title: Any) -> str:
    """
    Create a stable identity for a finding that survives re-scans.

    Only rule identity and title take part, so a finding keeps the same key
    across runs even when its description, evidence, or severity change. The
    key is what scan history compares on; it never encodes scan-specific data.
    """
    basis = "::".join(
        str(part or "").strip().lower()
        for part in (rule_id or finding_type, title)
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "identity::" + basis))

CheckStatus = Literal["COMPLETED", "PARTIAL", "FAILED", "UNAVAILABLE"]
DiscoveryOutcome = Literal["FOUND", "NOT_FOUND", "UNKNOWN"]

class EvidenceItem(BaseModel):
    """
    Normalized discrete evidence item extracted from analyzer output.
    The evidence_key must be deterministic for equivalent evidence
    and must not depend on random UUIDs.
    """
    source_module: str
    item_type: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    source: str
    evidence_key: str

class NormalizedCheckResult(BaseModel):
    """
    Normalized result container for a single analyzer execution.
    Decouples execution status (did the check run?) from discovery
    outcome (was evidence found?).
    """
    module: str
    status: CheckStatus
    outcome: DiscoveryOutcome
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    message: Optional[str] = None
    target: Optional[str] = None

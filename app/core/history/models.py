"""Stored shapes for scan history.

These models are what the SQLite store reads and writes. They are deliberately
sanitized versions of the in-memory scan objects: no raw evidence, no full
local paths, no credentials. See docs/PRIVACY.md for what is kept and why.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StoredFinding(BaseModel):
    """One finding as it is persisted for history and comparison."""

    identity_key: str
    title: str
    description: str = ""
    finding_type: str = "General"
    category: str = "Observation"
    severity: str = "Info"
    status: str = "Informational"
    source_module: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    verification: Optional[str] = None
    confidence: Optional[str] = None
    evidence_preview: List[str] = Field(default_factory=list)
    signature: str = ""

    @property
    def module(self) -> str:
        return (self.source_module or "").strip() or "unknown"


class ScanRecord(BaseModel):
    """One persisted scan, everything needed to review or compare it later."""

    id: int = 0
    scan_id: str = ""
    scan_type: str = ""
    status: str = ""
    started_at: str = ""
    finished_at: str = ""
    created_at: str = ""

    # Scoring snapshot. A record with score None is an honest "no number".
    score: Optional[int] = None
    band: str = ""
    methodology_version: str = ""
    coverage_key: str = ""
    confidence: str = ""

    target_label: str = ""
    counts: Dict[str, int] = Field(default_factory=dict)
    modules: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[StoredFinding] = Field(default_factory=list)
    risk: Dict[str, Any] = Field(default_factory=dict)

    @property
    def display_name(self) -> str:
        label = self.target_label or self.scan_type or "Scan"
        return f"{self.scan_type}: {label}" if self.target_label else label

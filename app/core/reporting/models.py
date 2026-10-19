"""The single report bundle.

JSON, CSV, and PDF all render from this one object, and this object is built
from the one risk summary the dashboard uses. There is no second severity
calculation and no second scoring path anywhere in reporting, so a number in
a PDF cannot disagree with the number on screen.

Everything textual in here has already passed through the sanitizer.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = "dfa-report-v1"


class ReportFinding(BaseModel):
    identity_key: str
    title: str
    description: str = ""
    finding_type: str = ""
    category: str = ""
    severity: str = "Info"
    status: str = "Informational"
    module: str = "unknown"
    sources: List[str] = Field(default_factory=list)
    verification: str = "unknown"
    confidence: str = "low"
    why_it_matters: str = ""
    evidence: List[str] = Field(default_factory=list)


class ReportCoverage(BaseModel):
    name: str
    key: str = ""
    state: str = "unknown"
    note: str = ""


class ReportAction(BaseModel):
    action_key: str
    title: str
    priority: str = "Low"
    module: str = "unknown"
    why_it_matters: str = ""
    steps: List[str] = Field(default_factory=list)
    docs: List[Dict[str, str]] = Field(default_factory=list)
    verification: str = "unknown"
    confidence: str = "low"
    verify_first: bool = False
    user_state: str = "pending"
    present_in_latest_scan: bool = True
    note: str = ""


class ReportAssessment(BaseModel):
    scan_type: str = ""
    status: str = ""
    target_label: str = ""
    started_at: str = ""
    finished_at: str = ""

    score: Optional[int] = None
    band: str = ""
    score_available: bool = False
    unavailable_reason: str = ""
    points: float = 0.0
    confidence: str = "low"
    confidence_reasons: List[str] = Field(default_factory=list)

    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    counts: Dict[str, int] = Field(default_factory=dict)
    factors: List[Dict[str, str]] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list)

    methodology_version: str = ""
    coverage_key: str = ""


class ReportBundle(BaseModel):
    """Everything a report needs, and nothing that is not shareable."""

    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    application: str = "Digital Footprint Analyzer"
    assessment: ReportAssessment = Field(default_factory=ReportAssessment)
    coverage: List[ReportCoverage] = Field(default_factory=list)
    findings: List[ReportFinding] = Field(default_factory=list)
    actions: List[ReportAction] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    is_empty: bool = False
    empty_reason: str = ""

    @property
    def title(self) -> str:
        label = self.assessment.target_label or self.assessment.scan_type or "Scan"
        return f"{self.assessment.scan_type or 'Scan'} report — {label}" \
            if self.assessment.target_label else f"{self.assessment.scan_type or 'Scan'} report"

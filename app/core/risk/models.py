"""Data shapes for the exposure model.

Every field is either derived from findings, derived from recorded module
coverage, or a fixed methodology constant. The models are pydantic so the
report exporters can serialize the exact object the dashboard displayed.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# Bump when the weights, bands, or gating rules change. Scan history only
# compares scores that share a methodology version.
METHODOLOGY_VERSION = "exposure-v1"

# Bands, as (minimum score, label). The score is 0-100.
BAND_TABLE = (
    (76, "High"),
    (51, "Elevated"),
    (25, "Moderate"),
    (1, "Low"),
    (0, "None detected"),
)

BAND_INDETERMINATE = "Indeterminate"


class ModuleCoverage(BaseModel):
    """How well one module covered its area during a scan."""

    name: str
    key: str
    state: str          # completed | limited | failed | unavailable | skipped | unknown
    note: str = ""


class RiskComponent(BaseModel):
    """One distinct issue contributing to (or excluded from) the score."""

    identity_key: str
    title: str
    module: str
    severity: str
    verification: str
    confidence: str
    contribution: float
    counted: bool = True
    capped: bool = False
    why_it_matters: str = ""
    sources: List[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    """A stated reason the score is what it is."""

    name: str
    detail: str


class RiskSummary(BaseModel):
    """The whole exposure picture for one scan."""

    methodology_version: str = METHODOLOGY_VERSION
    score: Optional[int] = None
    band: str = BAND_INDETERMINATE
    score_available: bool = False
    unavailable_reason: str = ""
    points: float = 0.0
    confidence: str = "low"
    confidence_reasons: List[str] = Field(default_factory=list)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    counts: Dict[str, int] = Field(default_factory=dict)
    components: List[RiskComponent] = Field(default_factory=list)
    top_findings: List[RiskComponent] = Field(default_factory=list)
    factors: List[RiskFactor] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list)
    modules: List[ModuleCoverage] = Field(default_factory=list)
    coverage_key: str = ""
    distinct_issues: int = 0

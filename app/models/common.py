from pydantic import BaseModel, Field
from typing import List, Optional, Any

class Recommendation(BaseModel):
    title: str
    description: str
    priority: str  # High, Medium, Low
    action_availability: bool = False
    remediation_type: Optional[str] = None
    instructions: Optional[str] = None

class Risk(BaseModel):
    risk_type: str
    severity: str  # Critical, High, Medium, Low, Info
    impact: str
    likelihood: str
    explanation: str

class Finding(BaseModel):
    finding_id: str
    finding_type: str
    title: str
    description: str
    evidence: Optional[Any] = None
    severity: str
    status: str
    category: str = "Observation"
    rule_id: Optional[str] = None
    limitations: Optional[str] = None

    # Provenance. All optional so every existing construction keeps working;
    # the findings normalizer fills them in when the source is known.
    source_module: Optional[str] = None      # system | browser | file_metadata | email | username
    sources: List[str] = Field(default_factory=list)  # every module that reported this issue
    identity_key: Optional[str] = None       # stable across scans, used for history + dedup
    verification: Optional[str] = None       # direct-observation | provider-verified | http-verified | provider-reported | unconfirmed | unknown
    confidence: Optional[str] = None         # high | medium | low

class FootprintData(BaseModel):
    category: str
    subcategory: str
    source: str
    data_type: str
    value: Any
    sensitivity: str

class ScanResult(BaseModel):
    scan_id: str
    analysis_mode: str
    scan_type: str
    scan_category: str
    status: str
    message: Optional[str] = None
    footprint_data: List[FootprintData] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    risks: List[Risk] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)

    # Scan metadata. Timestamps are ISO-8601 UTC strings; module_coverage is an
    # authoritative per-module status list produced by the scan controller when
    # the scan coordinates several modules (Full Scan). Results built outside
    # the controller leave it None and coverage is derived from result signals.
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    module_coverage: Optional[List[dict]] = None

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

"""Risk intelligence: one explainable exposure summary per scan.

The score is derived only from normalized findings and recorded module
coverage. Nothing here invents a number: when a scan cannot support a score,
``score`` is None and the band says so. See docs/RISK_METHODOLOGY.md.
"""

from app.core.risk.models import (
    METHODOLOGY_VERSION,
    RiskComponent,
    RiskFactor,
    RiskSummary,
    ModuleCoverage,
)
from app.core.risk.scoring import build_risk_summary

__all__ = [
    "METHODOLOGY_VERSION",
    "RiskComponent",
    "RiskFactor",
    "RiskSummary",
    "ModuleCoverage",
    "build_risk_summary",
]

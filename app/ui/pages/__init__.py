"""Expanded pages: assessment, evidence, action centre, and scan history.

These pages are appended after Settings so the original four pages keep their
positions. They read the same RiskSummary, coverage, and remediation objects
as the dashboard, so no page can disagree with another.
"""

from app.ui.pages.actions import ActionCentrePage
from app.ui.pages.assessment import AssessmentPage
from app.ui.pages.base import ThemedPage
from app.ui.pages.evidence import EvidencePage
from app.ui.pages.history import HistoryPage

__all__ = [
    "ActionCentrePage",
    "AssessmentPage",
    "EvidencePage",
    "HistoryPage",
    "ThemedPage",
]

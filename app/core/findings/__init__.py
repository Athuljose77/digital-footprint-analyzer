from app.core.findings.models import EvidenceItem, NormalizedCheckResult
from app.core.findings.processor import FindingsProcessor
from app.core.findings.adapters import (
    adapt_email_result,
    adapt_username_result,
    adapt_system_result,
    adapt_file_metadata_result,
    adapt_browser_result,
)

__all__ = [
    "EvidenceItem",
    "NormalizedCheckResult",
    "FindingsProcessor",
    "adapt_email_result",
    "adapt_username_result",
    "adapt_system_result",
    "adapt_file_metadata_result",
    "adapt_browser_result",
]

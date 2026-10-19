"""Local scan history: persistence, sanitization, and comparison.

Nothing in this package performs network requests or leaves the machine. The
only artifact it creates is a SQLite database the user can delete from the UI
or from disk. See docs/PRIVACY.md.
"""

from app.core.history.compare import (
    MODIFIED,
    NEW,
    NOT_RECHECKED,
    RESOLVED,
    UNCHANGED,
    FindingChange,
    ScanComparison,
    change_label,
    compare_scans,
)
from app.core.history.models import ScanRecord, StoredFinding
from app.core.history.store import (
    HistoryStoreError,
    ScanHistoryStore,
    default_db_path,
    default_store,
    record_from_result,
    reset_default_store,
    utc_now_iso,
)

__all__ = [
    "MODIFIED",
    "NEW",
    "NOT_RECHECKED",
    "RESOLVED",
    "UNCHANGED",
    "FindingChange",
    "ScanComparison",
    "change_label",
    "compare_scans",
    "ScanRecord",
    "StoredFinding",
    "HistoryStoreError",
    "ScanHistoryStore",
    "default_db_path",
    "default_store",
    "record_from_result",
    "reset_default_store",
    "utc_now_iso",
]

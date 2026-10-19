"""Comparison between two stored scans.

The rules that matter:

* A finding is only called **resolved** when the module that produced it
  actually ran in the newer scan. If that module failed, was unavailable, or
  was skipped, the finding is **not rechecked** instead — absence of evidence
  is never reported as an improvement.
* Findings are matched on their stable identity key, so it does not matter
  which scan produced which random id.
* Scores are only compared when both scans used the same methodology version
  *and* covered the same modules. Otherwise the delta is withheld and the
  reason is stated.
"""

from typing import Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field

from app.core import scan_coverage
from app.core.findings_processor import _get_severity_rank
from app.core.history.models import ScanRecord, StoredFinding

NEW = "new"
UNCHANGED = "unchanged"
RESOLVED = "resolved"
MODIFIED = "modified"
NOT_RECHECKED = "not_rechecked"

CHANGE_ORDER = (NEW, MODIFIED, RESOLVED, NOT_RECHECKED, UNCHANGED)


class FindingChange(BaseModel):
    """One finding's fate between two scans."""

    identity_key: str
    title: str
    change: str
    module: str = "unknown"
    severity_before: Optional[str] = None
    severity_after: Optional[str] = None
    status_before: Optional[str] = None
    status_after: Optional[str] = None
    verification: Optional[str] = None
    confidence: Optional[str] = None
    evidence_preview: List[str] = Field(default_factory=list)
    is_regression: bool = False
    note: str = ""


class CoverageChange(BaseModel):
    """One module's coverage difference between two scans."""

    name: str
    key: str
    before: str
    after: str


class _ScoreFields(TypedDict):
    """The score-comparison fields, typed so they can seed ScanComparison."""

    score_before: Optional[int]
    score_after: Optional[int]
    score_delta: Optional[int]
    score_comparable: bool
    score_note: str


class ScanComparison(BaseModel):
    """Full difference between two stored scans."""

    older_id: int = 0
    newer_id: int = 0
    older_finished_at: str = ""
    newer_finished_at: str = ""
    counts: Dict[str, int] = Field(default_factory=dict)
    changes: List[FindingChange] = Field(default_factory=list)
    coverage_changes: List[CoverageChange] = Field(default_factory=list)

    score_before: Optional[int] = None
    score_after: Optional[int] = None
    score_delta: Optional[int] = None
    score_comparable: bool = False
    score_note: str = ""

    resolved_confidence: str = "low"
    resolved_note: str = ""
    headline: str = ""

    @property
    def regressions(self) -> List[FindingChange]:
        return [c for c in self.changes if c.is_regression]


def _severity_rank(value: Optional[str]) -> int:
    return _get_severity_rank(str(value or "Info"))


def _coverage_states(record: ScanRecord) -> Dict[str, str]:
    states: Dict[str, str] = {}
    for module in record.modules or []:
        if not isinstance(module, dict):
            continue
        key = str(module.get("key") or scan_coverage.module_key(module.get("name", "")))
        states[key] = str(module.get("state") or scan_coverage.UNKNOWN)
    return states


def _module_covered_in_newer(module: str, states: Dict[str, str]) -> bool:
    """True only when the newer scan actually re-examined this module's area."""
    state = states.get((module or "").strip() or "unknown")
    return state in scan_coverage.EVIDENCE_STATES


def compare_scans(older: ScanRecord, newer: ScanRecord) -> ScanComparison:
    """Compare an older stored scan against a newer one."""
    older_findings = {f.identity_key: f for f in older.findings}
    newer_findings = {f.identity_key: f for f in newer.findings}
    newer_states = _coverage_states(newer)

    changes: List[FindingChange] = []

    for key, finding in newer_findings.items():
        previous = older_findings.get(key)
        if previous is None:
            changes.append(FindingChange(
                identity_key=key,
                title=finding.title,
                change=NEW,
                module=finding.module,
                severity_after=finding.severity,
                status_after=finding.status,
                verification=finding.verification,
                confidence=finding.confidence,
                evidence_preview=list(finding.evidence_preview),
                is_regression=_severity_rank(finding.severity) >= _severity_rank("High"),
                note=_severity_note(None, finding.severity),
            ))
            continue

        if previous.signature and previous.signature == finding.signature:
            changes.append(FindingChange(
                identity_key=key,
                title=finding.title,
                change=UNCHANGED,
                module=finding.module,
                severity_before=previous.severity,
                severity_after=finding.severity,
                status_before=previous.status,
                status_after=finding.status,
                verification=finding.verification,
                confidence=finding.confidence,
                evidence_preview=list(finding.evidence_preview),
            ))
            continue

        worse = _severity_rank(finding.severity) > _severity_rank(previous.severity)
        changes.append(FindingChange(
            identity_key=key,
            title=finding.title,
            change=MODIFIED,
            module=finding.module,
            severity_before=previous.severity,
            severity_after=finding.severity,
            status_before=previous.status,
            status_after=finding.status,
            verification=finding.verification,
            confidence=finding.confidence,
            evidence_preview=list(finding.evidence_preview),
            is_regression=worse,
            note=_severity_note(previous.severity, finding.severity),
        ))

    for key, finding in older_findings.items():
        if key in newer_findings:
            continue
        covered = _module_covered_in_newer(finding.module, newer_states)
        changes.append(FindingChange(
            identity_key=key,
            title=finding.title,
            change=RESOLVED if covered else NOT_RECHECKED,
            module=finding.module,
            severity_before=finding.severity,
            verification=finding.verification,
            confidence=finding.confidence,
            evidence_preview=list(finding.evidence_preview),
            note=("Not detected again in a scan where this module completed."
                  if covered else
                  "This module did not complete in the newer scan, so this "
                  "finding was not rechecked."),
        ))

    changes.sort(key=lambda c: (CHANGE_ORDER.index(c.change),
                                -_severity_rank(c.severity_after or c.severity_before),
                                c.title.lower()))

    counts = {name: 0 for name in CHANGE_ORDER}
    for change in changes:
        counts[change.change] += 1

    coverage_changes = _coverage_differences(older, newer)
    score_fields = _score_comparison(older, newer, newer_states)

    gaps = [str(m.get("name")) for m in (newer.modules or [])
            if isinstance(m, dict) and str(m.get("state")) in scan_coverage.UNCOVERED_STATES]
    if not (newer.modules or []):
        resolved_confidence = "low"
        resolved_note = (
            "The newer scan did not record module coverage, so an absent "
            "finding is only 'not rechecked' rather than resolved.")
    elif gaps:
        resolved_confidence = "low"
        resolved_note = (
            "Some modules did not complete in the newer scan, so findings from "
            f"them are only 'not rechecked': {', '.join(gaps)}.")
    else:
        resolved_confidence = "high"
        resolved_note = (
            "Every module in the newer scan completed, so 'resolved' means the "
            "issue was not detected again.")

    headline = _headline(counts, changes, score_fields)

    return ScanComparison(
        older_id=older.id,
        newer_id=newer.id,
        older_finished_at=older.finished_at,
        newer_finished_at=newer.finished_at,
        counts=counts,
        changes=changes,
        coverage_changes=coverage_changes,
        resolved_confidence=resolved_confidence,
        resolved_note=resolved_note,
        headline=headline,
        **score_fields,
    )


def _severity_note(before: Optional[str], after: Optional[str]) -> str:
    if before is None:
        return f"Not present in the earlier scan; now {after}."
    if _severity_rank(after) > _severity_rank(before):
        return f"Severity increased from {before} to {after}."
    if _severity_rank(after) < _severity_rank(before):
        return f"Severity decreased from {before} to {after}."
    return "Details changed since the earlier scan."


def _coverage_differences(older: ScanRecord, newer: ScanRecord) -> List[CoverageChange]:
    before = _coverage_states(older)
    after = _coverage_states(newer)
    names = {str(m.get("key")): str(m.get("name")) for m in (newer.modules or [])
             if isinstance(m, dict)}
    for module in older.modules or []:
        if isinstance(module, dict):
            names.setdefault(str(module.get("key")), str(module.get("name")))

    differences: List[CoverageChange] = []
    for key in sorted(set(before) | set(after)):
        old_state = before.get(key, scan_coverage.UNKNOWN)
        new_state = after.get(key, scan_coverage.UNKNOWN)
        if old_state != new_state:
            differences.append(CoverageChange(
                name=names.get(key, key), key=key,
                before=old_state, after=new_state))
    return differences


def _score_comparison(older: ScanRecord, newer: ScanRecord,
                      newer_states: Dict[str, str]) -> _ScoreFields:
    before, after = older.score, newer.score

    if before is None or after is None:
        return {
            "score_before": before,
            "score_after": after,
            "score_delta": None,
            "score_comparable": False,
            "score_note": ("At least one of these scans did not produce a score, "
                           "so no change can be shown."),
        }

    if older.methodology_version != newer.methodology_version:
        return {
            "score_before": before,
            "score_after": after,
            "score_delta": None,
            "score_comparable": False,
            "score_note": (f"Scored with different methodology versions "
                           f"({older.methodology_version or 'unknown'} vs "
                           f"{newer.methodology_version or 'unknown'}), so the "
                           "numbers are not comparable."),
        }

    if older.coverage_key != newer.coverage_key or not newer_states:
        return {
            "score_before": before,
            "score_after": after,
            "score_delta": None,
            "score_comparable": False,
            "score_note": ("The two scans covered different modules, so a score "
                           "change would reflect coverage, not exposure."),
        }

    return {
        "score_before": before,
        "score_after": after,
        "score_delta": after - before,
        "score_comparable": True,
        "score_note": "Both scans used the same methodology and coverage.",
    }


def _headline(counts: Dict[str, int], changes: List[FindingChange],
              score_fields: _ScoreFields) -> str:
    parts = []
    if counts.get(NEW):
        parts.append(f"{counts[NEW]} new")
    if counts.get(MODIFIED):
        parts.append(f"{counts[MODIFIED]} changed")
    if counts.get(RESOLVED):
        parts.append(f"{counts[RESOLVED]} resolved")
    if counts.get(NOT_RECHECKED):
        parts.append(f"{counts[NOT_RECHECKED]} not rechecked")
    if counts.get(UNCHANGED):
        parts.append(f"{counts[UNCHANGED]} unchanged")

    if score_fields.get("score_comparable"):
        delta = score_fields.get("score_delta")
        if delta == 0:
            parts.append("exposure score unchanged")
        elif isinstance(delta, int):
            parts.append(f"exposure score {'up' if delta > 0 else 'down'} "
                         f"{abs(delta)}")

    if not parts:
        return "No differences detected between these scans."
    return ", ".join(parts).capitalize() + "."


def change_label(change: str) -> str:
    """Human label for a change kind."""
    return {
        NEW: "New",
        UNCHANGED: "Unchanged",
        RESOLVED: "Resolved",
        MODIFIED: "Changed",
        NOT_RECHECKED: "Not rechecked",
    }.get(change, change)

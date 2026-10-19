"""Module coverage: one shared answer to "did this module run, and how well?".

The dashboard summary, the exposure scoring engine, and scan comparison all
read coverage through this module so they cannot disagree about whether a
scan actually covered something. A finding can never be reported as resolved
because a module silently did not run.

Two sources of truth, in priority order:

1. ``ScanResult.module_coverage`` — authoritative, written by the scan
   controller from the real per-module results.
2. Derivation from result signals (message, limitation findings, footprint
   categories) — used for results built outside the controller, including
   hand-built test fixtures and any caller that assembles a ScanResult itself.

The fallback deliberately mirrors the historical dashboard behaviour so
existing reports keep rendering identically.
"""

from typing import Dict, List, Mapping, Optional

# Canonical coverage vocabulary, shared by every consumer.
COMPLETED = "completed"
LIMITED = "limited"
FAILED = "failed"
UNAVAILABLE = "unavailable"
SKIPPED = "skipped"
UNKNOWN = "unknown"

COVERAGE_STATES = (COMPLETED, LIMITED, FAILED, UNAVAILABLE, SKIPPED, UNKNOWN)

# Coverage states that mean "this module produced usable evidence".
EVIDENCE_STATES = (COMPLETED, LIMITED)

# Coverage states that mean "absence of a finding here proves nothing".
UNCOVERED_STATES = (FAILED, UNAVAILABLE, SKIPPED, UNKNOWN)

# Display labels used by the Full Scan report, in report order.
MODULE_LABELS = (
    ("System", "System"),
    ("Browser", "Browser"),
    ("File & Metadata", "File"),
)

# Scan type -> stable machine key used by history and comparison.
MODULE_KEYS = {
    "System": "system",
    "Browser": "browser",
    "File & Metadata": "file_metadata",
    "File": "file_metadata",
    "Email": "email",
    "Username": "username",
    "Full Scan": "full",
}

NOTES = {
    COMPLETED: "Completed",
    LIMITED: "Had limitations — see limitation notes",
    FAILED: "Failed — module did not complete",
    UNAVAILABLE: "Unavailable on this platform — not scanned",
    SKIPPED: "Skipped — no file was selected",
    UNKNOWN: "No data",
}


def module_key(name: str) -> str:
    """Return the stable machine key for a module/scan name."""
    name = (name or "").strip()
    return MODULE_KEYS.get(name, name.lower().replace(" ", "_") or "unknown")


def state_from_status(status: Optional[str]) -> str:
    """Map a module ScanResult status onto a coverage state."""
    normalized = (status or "").strip().upper()
    if normalized == "COMPLETED":
        return COMPLETED
    if normalized == "PARTIAL":
        return LIMITED
    if normalized == "ERROR":
        return FAILED
    if normalized == "UNAVAILABLE":
        return UNAVAILABLE
    return UNKNOWN


def reports_unavailable(result) -> bool:
    """True when a module finished but explicitly reported nothing to scan.

    Requires the explicit "Unavailable:" coverage record, so a message that
    merely mentions the word never downgrades a real scan.
    """
    for item in getattr(result, "footprint_data", None) or []:
        if (getattr(item, "subcategory", "") == "Scan Coverage"
                and str(getattr(item, "value", "")).startswith("Unavailable:")):
            return True
    return False


def state_for_result(result) -> str:
    """Coverage state for one module result, including unavailable sources."""
    state = state_from_status(getattr(result, "status", None))
    if state == COMPLETED and reports_unavailable(result):
        return UNAVAILABLE
    return state


def result_coverage_row(name: str, result) -> Dict[str, str]:
    """Coverage row for a single module result."""
    state = state_for_result(result)
    note = None
    if state == LIMITED:
        note = "Completed with limitations — see limitation notes"
    elif state == UNAVAILABLE:
        note = "Unavailable on this platform — not scanned"
    return coverage_row(name, state, note=note)


def coverage_row(name: str, state: str, note: Optional[str] = None,
                 key: Optional[str] = None) -> Dict[str, str]:
    """Build one normalized coverage row."""
    if state not in COVERAGE_STATES:
        state = UNKNOWN
    return {
        "name": name,
        "key": key or module_key(name),
        "state": state,
        "note": note if note is not None else NOTES[state],
    }


def coverage_from_module_results(
    module_results: Mapping[str, object],
    included: Optional[Dict[str, bool]] = None,
) -> List[Dict[str, str]]:
    """Build authoritative coverage rows from per-module ScanResults.

    Args:
        module_results: module key -> ScanResult (or None when never run).
        included: optional explicit inclusion map; a module explicitly marked
            False is reported as skipped rather than failed.
    """
    rows: List[Dict[str, str]] = []
    included = included or {}
    for name, label in MODULE_LABELS:
        key = module_key(name)
        if included.get(key) is False:
            rows.append(coverage_row(label, SKIPPED))
            continue
        result = module_results.get(key)
        if result is None:
            # The controller keys the optional File module as "file".
            result = module_results.get("file" if key == "file_metadata" else key)
        if result is None:
            rows.append(coverage_row(label, SKIPPED))
            continue
        rows.append(result_coverage_row(label, result))
    return rows


def _has_limitation(findings, *keywords) -> bool:
    return any(
        (getattr(f, "finding_type", "") or "") == "Scan Limitation"
        and any(k.lower() in (getattr(f, "title", "") or "").lower()
                for k in keywords)
        for f in findings
    )


def _derive_from_signals(result) -> List[Dict[str, str]]:
    """Derive Full Scan coverage from a result that has no explicit coverage."""
    findings = list(getattr(result, "findings", None) or [])
    footprint = list(getattr(result, "footprint_data", None) or [])
    message = (getattr(result, "message", "") or "").lower()
    categories = {getattr(fd, "category", "") for fd in footprint}

    rows: List[Dict[str, str]] = []
    for category, label in MODULE_LABELS:
        if category == "File & Metadata" and "no file selected" in message:
            rows.append(coverage_row(label, SKIPPED))
        elif _has_limitation(findings, label, category):
            if label == "Browser" and (
                "unavailable" in message or "not available" in message
            ):
                rows.append(coverage_row(
                    label, UNAVAILABLE,
                    note="Unavailable on this platform — not scanned"))
            else:
                rows.append(coverage_row(
                    label, LIMITED,
                    note="Had limitations — see limitation notes"))
        elif category in categories:
            rows.append(coverage_row(label, COMPLETED))
        else:
            rows.append(coverage_row(label, UNKNOWN))
    return rows


def _normalize_rows(raw_rows) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for entry in raw_rows or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("key") or "").strip()
        if not name:
            continue
        rows.append(coverage_row(
            name,
            str(entry.get("state") or UNKNOWN).strip().lower(),
            note=entry.get("note"),
            key=str(entry.get("key") or "") or None,
        ))
    return rows


def derive_scan_coverage(result) -> List[Dict[str, str]]:
    """Coverage rows for any finished scan result."""
    if result is None:
        return []
    scan_type = getattr(result, "scan_type", "") or ""
    if scan_type == "Full Scan":
        explicit = getattr(result, "module_coverage", None)
        if explicit:
            return _normalize_rows(explicit)
        return _derive_from_signals(result)
    state = state_from_status(getattr(result, "status", None))
    return [result_coverage_row(scan_type or "Unknown", result)]


def coverage_key(rows) -> str:
    """Comparable coverage signature: which modules ran and how well.

    Two scans may only have their scores compared when this signature
    matches; otherwise a score drop could simply mean "less was scanned".
    """
    parts = []
    for row in sorted(rows or [], key=lambda r: str(r.get("key", ""))):
        key = str(row.get("key") or "")
        state = str(row.get("state") or "")
        if state == COMPLETED:
            parts.append(f"{key}:full")
        elif state == LIMITED:
            parts.append(f"{key}:partial")
        else:
            parts.append(f"{key}:none")
    return "|".join(parts)


def uncovered_modules(rows) -> List[str]:
    """Names of modules whose absence of findings proves nothing."""
    return [str(r.get("name")) for r in rows or []
            if str(r.get("state")) in UNCOVERED_STATES]

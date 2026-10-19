"""Deterministic exposure scoring.

Method (documented in docs/RISK_METHODOLOGY.md):

1. Coverage first. Findings only exist for modules that ran, and every scan
   records per-module coverage. A module that failed, was unavailable, or was
   skipped contributes nothing and is reported as a gap.
2. Coverage and limitation findings are separated out. They describe the scan,
   not the user, and never raise the score.
3. Duplicate issues are collapsed by identity key, merging the modules and
   evidence that reported them, so one issue never counts twice.
4. Each distinct issue contributes severity points scaled by how strongly the
   evidence supports it (verification -> confidence).
5. One rule may contribute at most MAX_ISSUES_PER_RULE issues, so a single
   noisy source cannot dominate the score.
6. Points map onto a 0-100 index with a saturating curve; the band is read off
   that index.
7. If no exposure-capable module provided coverage, or the scan did not
   complete, the score is None with a stated reason rather than a number.
"""

import math
from typing import Dict, List, Optional, TypedDict

from app.core import scan_coverage
from app.core.findings_processor import COVERAGE_FINDING_TYPES, VERIFICATION_RANK, _get_severity_rank
from app.core.risk.explanations import why_it_matters
from app.core.risk.models import (
    BAND_INDETERMINATE,
    BAND_TABLE,
    METHODOLOGY_VERSION,
    ModuleCoverage,
    RiskComponent,
    RiskFactor,
    RiskSummary,
)

# Severity -> base points per distinct issue.
SEVERITY_WEIGHTS = {
    "Critical": 25.0,
    "High": 15.0,
    "Medium": 8.0,
    "Low": 3.0,
    "Info": 1.0,
}

# How strongly the evidence supports a finding, as a multiplier on its weight.
CONFIDENCE_FACTORS = {"high": 1.0, "medium": 0.7, "low": 0.5}
DEFAULT_CONFIDENCE_FACTOR = 0.5

# A single rule may contribute at most this many scored issues.
MAX_ISSUES_PER_RULE = 3

# Curve constant: points needed before the index approaches its ceiling.
SCORE_SCALE = 35.0

CONFIRMED_VERIFICATIONS = ("direct-observation", "provider-verified", "http-verified")
POTENTIAL_VERIFICATIONS = ("provider-reported", "unconfirmed")

# Modules whose findings can contribute to an exposure score.
EXPOSURE_MODULES = ("system", "browser", "file_metadata", "email", "username")

# A score is only offered for scans that actually completed work.
SCOREABLE_STATUSES = ("COMPLETED", "PARTIAL")


class _IssueRecord(TypedDict):
    """One distinct issue inside the scoring pass.

    An internal shape only: findings are collapsed into these records before
    weights are applied, so every key is typed exactly once.
    """

    key: str
    title: str
    severity: str
    verification: str
    confidence: Optional[str]
    module: str
    rule: str
    finding_type: str
    sources: List[str]
    why: str


def _confidence_factor(confidence: Optional[str]) -> float:
    return CONFIDENCE_FACTORS.get(
        str(confidence or "").strip().lower(), DEFAULT_CONFIDENCE_FACTOR)


def _module_of(finding) -> str:
    return str(getattr(finding, "source_module", "") or "").strip() or "unknown"


def _issue_key(finding) -> str:
    key = str(getattr(finding, "identity_key", "") or "").strip()
    if key:
        return key
    return f"{(finding.finding_type or '').strip()}::{(finding.title or '').strip()}"


def _is_coverage_finding(finding) -> bool:
    return str(getattr(finding, "finding_type", "") or "").strip() in COVERAGE_FINDING_TYPES


def _band_for(score: Optional[int]) -> str:
    if score is None:
        return BAND_INDETERMINATE
    for threshold, label in BAND_TABLE:
        if score >= threshold:
            return label
    return BAND_INDETERMINATE


def group_issues(findings) -> List[_IssueRecord]:
    """Collapse findings into distinct issues, merging provenance.

    The highest severity and the strongest verification win; every module that
    reported the issue is retained in ``sources`` so deduplication never
    discards where the evidence came from.
    """
    groups: Dict[str, _IssueRecord] = {}
    order: List[str] = []

    for finding in findings:
        key = _issue_key(finding)
        module = _module_of(finding)
        existing = groups.get(key)
        if existing is None:
            groups[key] = {
                "key": key,
                "title": finding.title,
                "severity": finding.severity,
                "verification": finding.verification or "unknown",
                "confidence": finding.confidence,
                "module": module,
                "rule": (finding.rule_id or finding.finding_type or "").strip(),
                "finding_type": finding.finding_type,
                "sources": list(dict.fromkeys(
                    [s for s in ([module] + list(finding.sources or [])) if s])),
                "why": why_it_matters(finding),
            }
            order.append(key)
            continue

        if _get_severity_rank(finding.severity) > _get_severity_rank(existing["severity"]):
            existing["severity"] = finding.severity
        current_rank = VERIFICATION_RANK.get(str(existing["verification"]), 0)
        new_rank = VERIFICATION_RANK.get(str(finding.verification or "unknown"), 0)
        if new_rank > current_rank:
            existing["verification"] = finding.verification or "unknown"
            existing["confidence"] = finding.confidence
        for source in [module] + list(finding.sources or []):
            if source and source not in existing["sources"]:
                existing["sources"].append(source)

    return [groups[key] for key in order]


def _build_components(issues: List[_IssueRecord]) -> List[RiskComponent]:
    """Turn distinct issues into weighted, explained components."""
    per_rule: Dict[str, int] = {}
    components: List[RiskComponent] = []

    for issue in issues:
        rule = str(issue["rule"] or "unclassified")
        per_rule[rule] = per_rule.get(rule, 0) + 1
        capped = per_rule[rule] > MAX_ISSUES_PER_RULE

        weight = SEVERITY_WEIGHTS.get(str(issue["severity"]), 1.0) * _confidence_factor(
            issue["confidence"])
        components.append(RiskComponent(
            identity_key=str(issue["key"]),
            title=str(issue["title"] or ""),
            module=str(issue["module"]),
            severity=str(issue["severity"] or "Info"),
            verification=str(issue["verification"] or "unknown"),
            confidence=str(issue["confidence"] or "unknown"),
            contribution=0.0 if capped else round(weight, 2),
            counted=not capped,
            capped=capped,
            why_it_matters=str(issue["why"]),
            sources=list(issue["sources"]),
        ))

    components.sort(key=lambda c: (-c.contribution, c.title.lower()))
    return components


def _coverage_gaps(modules) -> List[str]:
    return [m.name for m in modules if m.state in scan_coverage.UNCOVERED_STATES]


def _confidence_level(modules, potential_count: int):
    states = [m.state for m in modules]
    reasons: List[str] = []

    failed = sum(1 for s in states if s in (scan_coverage.FAILED, scan_coverage.UNAVAILABLE))
    uncovered = sum(1 for s in states if s in scan_coverage.UNCOVERED_STATES)
    partial = sum(1 for s in states if s == scan_coverage.LIMITED)

    if failed or uncovered >= 2:
        level = "low"
        reasons.append("one or more modules did not provide coverage")
    elif uncovered == 1 or partial:
        level = "medium"
        reasons.append("part of the scan completed with limitations")
    else:
        level = "high"
        reasons.append("every attempted module completed")

    if potential_count:
        reasons.append(f"{potential_count} finding(s) are reported but unverified")
    return level, reasons


def build_risk_summary(result) -> RiskSummary:
    """Build the full exposure summary for one finished scan."""
    findings = list(getattr(result, "findings", None) or [])
    coverage_rows = scan_coverage.derive_scan_coverage(result)
    modules = [ModuleCoverage(**row) for row in coverage_rows]

    exposure_findings = [f for f in findings if not _is_coverage_finding(f)]
    coverage_findings = [f for f in findings if _is_coverage_finding(f)]

    issues = group_issues(exposure_findings)
    components = _build_components(issues)
    points = round(sum(c.contribution for c in components), 2)

    covered = [m for m in modules
               if m.state in scan_coverage.EVIDENCE_STATES and m.key in EXPOSURE_MODULES]
    status = (getattr(result, "status", "") or "").strip().upper()
    score_available = bool(covered) and status in SCOREABLE_STATUSES

    unavailable_reason = ""
    if not score_available:
        if not modules:
            unavailable_reason = "The scan produced no module results to assess."
        elif status not in SCOREABLE_STATUSES:
            unavailable_reason = (
                f"The scan finished with status {status or 'unknown'}; an exposure "
                "score requires a completed or partially completed scan.")
        else:
            unavailable_reason = (
                "No module completed with usable coverage, so there is nothing to "
                "score. Absence of findings here does not mean absence of exposure.")

    score = (round(100 * (1 - math.exp(-points / SCORE_SCALE)))
             if score_available else None)

    confirmed = sum(1 for i in issues if i["verification"] in CONFIRMED_VERIFICATIONS)
    potential = sum(1 for i in issues if i["verification"] in POTENTIAL_VERIFICATIONS)

    severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for issue in issues:
        sev = str(issue["severity"] or "Info").strip().capitalize()
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    confidence, confidence_reasons = _confidence_level(modules, potential)

    reported_modules = len({f.source_module for f in exposure_findings if f.source_module})

    gaps = _coverage_gaps(modules)
    counts = {
        "distinct_issues": len(issues),
        "confirmed": confirmed,
        "potential": potential,
        "inconclusive": len(issues) - confirmed - potential,
        "coverage_findings": len(coverage_findings),
        "uncovered_modules": len(gaps),
        "collection_failures": sum(1 for m in modules if m.state == scan_coverage.FAILED),
        "unsupported_checks": sum(1 for m in modules if m.state == scan_coverage.UNAVAILABLE),
    }

    factors = [
        RiskFactor(
            name="Distinct issues",
            detail=(f"{len(issues)} distinct issue(s) after merging duplicate findings "
                    f"from {reported_modules} reporting module(s)."),
        ),
        RiskFactor(
            name="Severity weight",
            detail=(f"{points} point(s) from severity weights "
                    f"(Critical 25, High 15, Medium 8, Low 3, Info 1) scaled by "
                    "evidence confidence (verified 1.0, provider-reported 0.5, "
                    "unconfirmed 0.5)."),
        ),
        RiskFactor(
            name="Coverage",
            detail=(f"{len(covered)} of {len(modules)} module(s) produced usable "
                    f"coverage; gaps: {', '.join(gaps) if gaps else 'none'}."),
        ),
        RiskFactor(
            name="Methodology",
            detail=(f"{METHODOLOGY_VERSION}: index = round(100 x (1 - e^(-points/"
                    f"{int(SCORE_SCALE)}))), capped at 3 issues per rule."),
        ),
    ]

    caveats: List[str] = []
    if score_available and not issues:
        caveats.append(
            "No findings were detected in the modules that ran. That is not "
            "evidence that no exposure exists.")
    if gaps:
        caveats.append(
            "These modules did not provide usable coverage, so findings from "
            f"them are unknown: {', '.join(gaps)}.")
    if potential:
        caveats.append(
            f"{potential} finding(s) are reported but unverified; treat them as "
            "leads to check, not as established exposure.")
    if counts["inconclusive"]:
        caveats.append(
            f"{counts['inconclusive']} issue(s) could not be tied to a verified "
            "source and are shown for awareness only.")
    if not score_available and unavailable_reason:
        caveats.append(unavailable_reason)

    return RiskSummary(
        methodology_version=METHODOLOGY_VERSION,
        score=score,
        band=_band_for(score),
        score_available=score_available,
        unavailable_reason=unavailable_reason,
        points=points,
        confidence=confidence,
        confidence_reasons=confidence_reasons,
        severity_breakdown=severity_breakdown,
        counts=counts,
        components=components,
        top_findings=[c for c in components if c.counted][:5],
        factors=factors,
        caveats=caveats,
        modules=modules,
        coverage_key=scan_coverage.coverage_key(coverage_rows),
        distinct_issues=len(issues),
    )

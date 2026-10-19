"""Build the report bundle from a scan result.

The builder is the only place reports get their data. It consumes the same
:class:`~app.core.risk.models.RiskSummary` the dashboard renders and the same
remediation plan the action centre shows, sanitizes every string that came
from a scan, and records honestly when a scan had nothing to report.
"""

from typing import List, Optional

from app.core.history.sanitize import sanitize_evidence, sanitize_target, sanitize_text
from app.core.remediation.engine import ActionBoard, RemediationPlan
from app.core.reporting.models import (
    ReportAction,
    ReportAssessment,
    ReportBundle,
    ReportCoverage,
    ReportFinding,
)
from app.core.risk.explanations import methodology_limits, why_it_matters as explain
from app.core.risk.models import RiskSummary
from app.core.risk.scoring import build_risk_summary
from app.core.history.store import utc_now_iso

PROVENANCE_NOTE = (
    "Generated locally on this device from a single scan. No data was sent "
    "anywhere to produce this report."
)
SANITIZED_NOTE = (
    "Evidence is shortened and sensitive values (credentials, tokens, full "
    "file paths, email local parts) are masked. Re-run the scan for the raw "
    "values."
)


def _coverage_rows(risk: RiskSummary) -> List[ReportCoverage]:
    return [
        ReportCoverage(
            name=module.name,
            key=module.key,
            state=module.state,
            note=sanitize_text(module.note, limit=200),
        )
        for module in risk.modules
    ]


def _findings_from_result(result, risk: RiskSummary) -> List[ReportFinding]:
    """Findings ordered exactly like the scored components.

    Titles come from the scan, evidence previews are sanitized and capped, and
    the order follows the risk components so the report reads in the same
    priority order as the assessment.
    """
    by_key = {}
    for finding in getattr(result, "findings", None) or []:
        key = str(getattr(finding, "identity_key", "") or "")
        if not key:
            key = f"{(getattr(finding, 'finding_type', '') or '').strip()}::" \
                  f"{(getattr(finding, 'title', '') or '').strip()}"
        by_key.setdefault(key, finding)

    rows: List[ReportFinding] = []
    used = set()
    for component in risk.components:
        finding = by_key.get(component.identity_key)
        used.add(component.identity_key)
        rows.append(ReportFinding(
            identity_key=component.identity_key,
            title=sanitize_text(component.title, limit=200),
            description=sanitize_text(
                getattr(finding, "description", "") if finding else "", limit=400),
            finding_type=sanitize_text(
                getattr(finding, "finding_type", "") if finding else "", limit=80),
            category=sanitize_text(
                getattr(finding, "category", "") if finding else "", limit=80),
            severity=component.severity,
            status=sanitize_text(
                getattr(finding, "status", "") if finding else "", limit=60),
            module=component.module,
            sources=[str(s) for s in component.sources],
            verification=component.verification,
            confidence=component.confidence,
            why_it_matters=sanitize_text(component.why_it_matters, limit=400),
            evidence=sanitize_evidence(
                getattr(finding, "evidence", None) if finding else None),
        ))

    # Findings the scorer excluded (for example rule-capped duplicates) must
    # still be visible in the report rather than silently dropped.
    for key, finding in by_key.items():
        if key in used:
            continue
        rows.append(ReportFinding(
            identity_key=key,
            title=sanitize_text(getattr(finding, "title", ""), limit=200),
            description=sanitize_text(getattr(finding, "description", ""), limit=400),
            finding_type=sanitize_text(getattr(finding, "finding_type", ""), limit=80),
            category=sanitize_text(getattr(finding, "category", ""), limit=80),
            severity=str(getattr(finding, "severity", "") or "Info"),
            status=sanitize_text(getattr(finding, "status", ""), limit=60),
            module=str(getattr(finding, "source_module", "") or "unknown"),
            sources=[str(s) for s in (getattr(finding, "sources", None) or [])],
            verification=str(getattr(finding, "verification", "") or "unknown"),
            confidence=str(getattr(finding, "confidence", "") or "low"),
            why_it_matters=explain(finding),
            evidence=sanitize_evidence(getattr(finding, "evidence", None)),
        ))
    return rows


def _action_rows(plan: Optional[RemediationPlan],
                 board: Optional[ActionBoard]) -> List[ReportAction]:
    if plan is None:
        return []

    states = {}
    if board is not None:
        for item in list(board.items) + list(board.not_detected):
            states[item.action.action_key] = item

    rows: List[ReportAction] = []
    for action in plan.actions:
        item = states.get(action.action_key)
        rows.append(ReportAction(
            action_key=action.action_key,
            title=sanitize_text(action.title, limit=200),
            priority=action.priority,
            module=action.module,
            why_it_matters=sanitize_text(action.why_it_matters, limit=400),
            steps=[sanitize_text(step, limit=300) for step in action.steps],
            docs=[{"label": link.label, "url": link.url} for link in action.docs],
            verification=action.verification,
            confidence=action.confidence,
            verify_first=action.verify_first,
            user_state=item.state if item else "pending",
            present_in_latest_scan=True,
            note=sanitize_text(action.note, limit=300),
        ))

    if board is not None:
        for item in board.not_detected:
            rows.append(ReportAction(
                action_key=item.action.action_key,
                title=sanitize_text(item.action.title, limit=200),
                priority=item.action.priority,
                module=item.action.module,
                user_state=item.state,
                present_in_latest_scan=False,
                note=sanitize_text(item.status_note, limit=300),
            ))
    return rows


def build_report_bundle(
    result,
    risk_summary: Optional[RiskSummary] = None,
    plan: Optional[RemediationPlan] = None,
    board: Optional[ActionBoard] = None,
    target: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> ReportBundle:
    """Build the one bundle every exporter renders."""
    risk = risk_summary if risk_summary is not None else build_risk_summary(result)

    assessment = ReportAssessment(
        scan_type=str(getattr(result, "scan_type", "") or ""),
        status=str(getattr(result, "status", "") or ""),
        target_label=sanitize_target(target or ""),
        started_at=str(getattr(result, "started_at", "") or ""),
        finished_at=str(getattr(result, "finished_at", "") or ""),
        score=risk.score,
        band=risk.band,
        score_available=risk.score_available,
        unavailable_reason=sanitize_text(risk.unavailable_reason, limit=300),
        points=risk.points,
        confidence=risk.confidence,
        confidence_reasons=[sanitize_text(r, limit=200)
                            for r in risk.confidence_reasons],
        severity_breakdown=dict(risk.severity_breakdown),
        counts=dict(risk.counts),
        factors=[{"name": factor.name,
                  "detail": sanitize_text(factor.detail, limit=300)}
                 for factor in risk.factors],
        caveats=[sanitize_text(c, limit=300) for c in risk.caveats],
        methodology_version=risk.methodology_version,
        coverage_key=risk.coverage_key,
    )

    findings = _findings_from_result(result, risk)
    coverage = _coverage_rows(risk)

    is_empty = not findings
    empty_reason = ""
    if is_empty:
        if not coverage:
            empty_reason = "This scan recorded no findings and no module coverage."
        elif not risk.score_available:
            empty_reason = ("This scan recorded no findings, and no module "
                            "completed with usable coverage, so nothing could "
                            "be assessed.")
        else:
            empty_reason = ("No findings were detected in the modules that ran. "
                            "That is not evidence that no exposure exists.")

    notes = [PROVENANCE_NOTE, SANITIZED_NOTE]
    notes.extend(methodology_limits())
    if risk.score_available and not findings:
        notes.append("An exposure score of 0 means nothing was detected, not "
                     "that nothing exists.")

    return ReportBundle(
        generated_at=generated_at or utc_now_iso(),
        assessment=assessment,
        coverage=coverage,
        findings=findings,
        actions=_action_rows(plan, board),
        notes=notes,
        is_empty=is_empty,
        empty_reason=empty_reason,
    )

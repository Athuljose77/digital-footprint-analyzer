"""Turn findings into a prioritised action plan.

An action exists only because a finding exists. Coverage findings are
excluded (they describe the scan), unknown finding types yield no advice at
all, and the count of findings without a mapped action is reported instead of
being silently dropped.
"""

import re
from typing import Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from app.core.findings_processor import VERIFICATION_RANK, _get_severity_rank
from app.core.history.sanitize import sanitize_target, sanitize_text
from app.core.remediation.catalogue import (
    COVERAGE_TYPES,
    TEMPLATES,
    resolved_docs,
    template_for,
)
from app.core.remediation.models import (
    COMPLETED,
    DISMISSED,
    PENDING,
    RemediationAction,
)

PRIORITY_BY_SEVERITY = {
    "Critical": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Low",
}
PRIORITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}

# A finding is only as good as the evidence behind it; anything not directly
# observed should be confirmed before the user spends effort on it.
VERIFY_FIRST_VERIFICATIONS = ("unconfirmed", "provider-reported", "unknown", "")

MAX_FINDING_TITLES = 5

_SUBJECT_PATTERNS = (
    re.compile(r"^Exposed in (?P<subject>.+)$", re.IGNORECASE),
    re.compile(r"^Confirmed Breach Exposure: (?P<subject>.+)$", re.IGNORECASE),
    re.compile(r"^Public Profile Discovered on (?P<subject>.+)$", re.IGNORECASE),
    re.compile(r"^(?:Sensitive|Device) Metadata (?:Detected )?(?:in|for) (?P<subject>.+)$",
               re.IGNORECASE),
    re.compile(r"^.+?\bon (?P<subject>.+)$", re.IGNORECASE),
    re.compile(r"^.+?:\s*(?P<subject>.+)$", re.IGNORECASE),
)


class ActionItem(BaseModel):
    """An action together with the user's own state for it."""

    action: RemediationAction
    state: str = PENDING
    present_in_latest_scan: bool = True
    status_note: str = ""


class ActionBoard(BaseModel):
    """Everything the action centre needs for one render."""

    items: List[ActionItem] = Field(default_factory=list)
    not_detected: List[ActionItem] = Field(default_factory=list)
    pending: int = 0
    completed: int = 0
    dismissed: int = 0
    completed_not_verified: int = 0
    note: str = ""

    @property
    def actionable(self) -> List[ActionItem]:
        return [i for i in self.items if i.state == PENDING]


class RemediationPlan(BaseModel):
    """Prioritised actions for one scan."""

    actions: List[RemediationAction] = Field(default_factory=list)
    unmapped_findings: int = 0
    unmapped_types: List[str] = Field(default_factory=list)
    note: str = ""


def _priority_for(severity: str) -> str:
    return PRIORITY_BY_SEVERITY.get(str(severity or "Info").strip().capitalize(),
                                    "Low")


def _subject_for(title: str) -> str:
    text = sanitize_text(title or "", limit=160)
    for pattern in _SUBJECT_PATTERNS:
        match = pattern.match(text)
        if match:
            subject = sanitize_target(match.group("subject").strip())
            if subject:
                return subject
    return ""


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return slug[:48] or "general"


def _action_key(template_name: str, template, subject: str) -> str:
    if template.subject == "suffix":
        return f"{template.key_prefix}:{_slug(subject)}"
    return template.key_prefix


def _fill(text: str, subject: str) -> str:
    if "{subject}" not in text:
        return text
    return text.replace("{subject}", subject or "this account")


def _severity_rank(value: str) -> int:
    return _get_severity_rank(str(value or "Info"))


def _iter_findings(source) -> Tuple[List, bool]:
    """Accept either a ScanResult or a list of findings."""
    findings = getattr(source, "findings", None)
    if findings is None:
        return list(source or []), not isinstance(source, (list, tuple))
    return list(findings or []), True


def build_plan(source) -> RemediationPlan:
    """Build the prioritised action plan for a scan result or finding list."""
    findings, _ = _iter_findings(source)

    merged: Dict[str, dict] = {}
    unmapped_types: List[str] = []

    for finding in findings:
        finding_type = str(getattr(finding, "finding_type", "") or "").strip()
        if finding_type in COVERAGE_TYPES:
            continue

        template_name, template = template_for(finding)
        if template is None:
            if finding_type and finding_type not in unmapped_types:
                unmapped_types.append(finding_type)
            continue

        subject = _subject_for(getattr(finding, "title", ""))
        key = _action_key(template_name, template, subject)
        severity = str(getattr(finding, "severity", "") or "Info")
        verification = str(getattr(finding, "verification", "") or "unknown")

        entry = merged.get(key)
        if entry is None:
            entry = {
                "template_name": template_name,
                "template": template,
                "subject": subject,
                "severity": severity,
                "verification": verification,
                "confidence": getattr(finding, "confidence", None) or "low",
                "module": str(getattr(finding, "source_module", "") or "unknown"),
                "finding_titles": [],
                "rule_ids": [],
            }
            merged[key] = entry

        if _severity_rank(severity) > _severity_rank(entry["severity"]):
            entry["severity"] = severity
        if (VERIFICATION_RANK.get(verification, 0)
                > VERIFICATION_RANK.get(str(entry["verification"]), 0)):
            entry["verification"] = verification
            entry["confidence"] = getattr(finding, "confidence", None) or entry["confidence"]

        title = sanitize_text(getattr(finding, "title", ""), limit=160)
        if title and title not in entry["finding_titles"] and \
                len(entry["finding_titles"]) < MAX_FINDING_TITLES:
            entry["finding_titles"].append(title)
        rule_id = str(getattr(finding, "rule_id", "") or "").strip()
        if rule_id and rule_id not in entry["rule_ids"]:
            entry["rule_ids"].append(rule_id)

    actions: List[RemediationAction] = []
    for key, entry in merged.items():
        template = entry["template"]
        subject = entry["subject"]
        verification = str(entry["verification"] or "unknown")
        actions.append(RemediationAction(
            action_key=key,
            title=_fill(template.title, subject),
            priority=_priority_for(entry["severity"]),
            module=_module_for(entry),
            why_it_matters=_fill(template.why, subject),
            steps=[_fill(step, subject) for step in template.steps],
            docs=resolved_docs(entry["template_name"], subject),
            finding_titles=list(entry["finding_titles"]),
            rule_ids=list(entry["rule_ids"]),
            severity=str(entry["severity"]),
            verification=verification,
            confidence=str(entry["confidence"] or "low"),
            verify_first=verification.strip().lower() in VERIFY_FIRST_VERIFICATIONS,
            note=template.note,
        ))

    actions.sort(key=lambda a: (-PRIORITY_RANK.get(a.priority, 0),
                                not a.verify_first,
                                a.title.lower()))

    note = ""
    if not actions and unmapped_types:
        note = ("Findings were recorded that have no mapped remediation action, "
                "so no advice is shown for them.")
    elif not actions:
        note = ("No findings were detected that map to a remediation action, so "
                "there is nothing to do here.")

    return RemediationPlan(
        actions=actions,
        unmapped_findings=sum(
            1 for f in findings
            if str(getattr(f, "finding_type", "") or "") not in COVERAGE_TYPES
            and template_for(f)[0] is None),
        unmapped_types=unmapped_types,
        note=note,
    )


def _module_for(entry: dict) -> str:
    return str(entry.get("module") or "unknown")


def plan_with_states(plan: RemediationPlan, store) -> ActionBoard:
    """Attach the user's persisted state to a plan and summarise it.

    ``store`` is an :class:`~app.core.remediation.store.ActionStateStore`.
    Actions the user marked done but that are no longer detected are listed
    separately and are never described as technically verified.
    """
    if store is not None:
        try:
            store.sync(plan.actions)
        except Exception:
            # A read-only or unavailable state store must not break the page.
            pass

    states = {}
    if store is not None:
        try:
            states = store.all_states()
        except Exception:
            states = {}

    current_keys = {a.action_key for a in plan.actions}
    items: List[ActionItem] = []
    not_detected: List[ActionItem] = []

    for action in plan.actions:
        record = states.get(action.action_key) or {}
        state = str(record.get("state") or PENDING)
        status_note = ""
        if state == COMPLETED:
            status_note = ("Marked complete by you; this is your own mark, not a "
                           "technical verification. Re-run the scan to check "
                           "whether it is still detected.")
        elif state == DISMISSED:
            status_note = "Dismissed by you; it is still present in the latest scan."
        elif action.verify_first:
            status_note = ("The scan could not confirm this evidence directly, so "
                           "check it before acting.")
        items.append(ActionItem(action=action, state=state,
                                present_in_latest_scan=True,
                                status_note=status_note))

    for key, record in states.items():
        if key in current_keys:
            continue
        if str(record.get("state")) != COMPLETED:
            continue
        action = RemediationAction(
            action_key=key,
            title=str(record.get("title") or key),
            priority=str(record.get("priority") or "Low"),
            module=str(record.get("module") or "unknown"),
            why_it_matters="",
            steps=[],
            docs=[],
            finding_titles=[],
            verification="unknown",
            confidence="low",
            verify_first=False,
            note=("Not detected in the latest scan. This is your own mark, not a "
                  "technical verification that the issue is gone."),
        )
        not_detected.append(ActionItem(
            action=action, state=COMPLETED, present_in_latest_scan=False,
            status_note=("Completed by you and no longer detected in the latest "
                         "scan (your mark, not a technical verification).")))

    pending = sum(1 for i in items if i.state == PENDING)
    completed = sum(1 for i in items if i.state == COMPLETED)
    dismissed = sum(1 for i in items if i.state == DISMISSED)

    return ActionBoard(
        items=items,
        not_detected=not_detected,
        pending=pending,
        completed=completed,
        dismissed=dismissed,
        completed_not_verified=len(not_detected),
        note=plan.note,
    )


def pending_action_count(source, store=None) -> Optional[int]:
    """Pending action count for the dashboard, or None when not applicable."""
    plan = build_plan(source)
    board = plan_with_states(plan, store)
    return board.pending


def arrange_steps(plan: RemediationPlan) -> Sequence[Tuple[str, List[str]]]:
    """Group step text by priority, in priority order."""
    grouped: Dict[str, List[str]] = {}
    for action in plan.actions:
        grouped.setdefault(action.priority, []).append(action.title)
    return [(priority, grouped[priority]) for priority in
            sorted(grouped, key=lambda p: -PRIORITY_RANK.get(p, 0))]

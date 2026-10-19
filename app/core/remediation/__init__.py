"""Remediation: what to actually do about the findings.

Actions are derived strictly from findings through a fixed rule -> action
mapping. There are no generic tips: a scan with nothing to fix produces an
empty plan, not advice.

User state (pending / completed / dismissed) is kept separately from the
findings, because "I handled this" is the user's statement and is never
presented as a technical verification that the issue is gone.
"""

from app.core.remediation.engine import (
    ActionBoard,
    ActionItem,
    RemediationPlan,
    build_plan,
    pending_action_count,
    plan_with_states,
)
from app.core.remediation.models import DocLink, RemediationAction

__all__ = [
    "ActionBoard",
    "ActionItem",
    "RemediationPlan",
    "build_plan",
    "pending_action_count",
    "plan_with_states",
    "DocLink",
    "RemediationAction",
]

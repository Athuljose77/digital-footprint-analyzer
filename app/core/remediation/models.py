"""Shapes for the action centre."""

from typing import List, Optional

from pydantic import BaseModel, Field

# User-facing state of an action.
PENDING = "pending"
COMPLETED = "completed"
DISMISSED = "dismissed"
ACTION_STATES = (PENDING, COMPLETED, DISMISSED)


class DocLink(BaseModel):
    """A documentation link. Every URL shipped here was checked to resolve."""

    label: str
    url: str


class RemediationAction(BaseModel):
    """One prioritised, explained action."""

    action_key: str
    title: str
    priority: str                  # Critical | High | Medium | Low
    module: str
    why_it_matters: str
    steps: List[str] = Field(default_factory=list)
    docs: List[DocLink] = Field(default_factory=list)

    # Provenance of the findings that produced this action.
    finding_titles: List[str] = Field(default_factory=list)
    rule_ids: List[str] = Field(default_factory=list)
    severity: str = "Info"
    verification: str = "unknown"
    confidence: str = "low"
    verify_first: bool = False
    note: str = ""

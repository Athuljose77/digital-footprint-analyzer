from typing import Optional
from app.models.common import Finding
from app.core.findings.models import NormalizedCheckResult, EvidenceItem, make_finding_id

def rule_usr_profile_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    USR-PROFILE-001: Discovered public profile for queried username.
    Category: Observation
    Severity: Info
    Status: Informational
    """
    if item.source_module != "username" or item.item_type != "social_profile":
        return None

    platform = item.properties.get("platform", "Unknown Platform")
    url = item.properties.get("profile_url", "")

    return Finding(
        finding_id=make_finding_id("USR-PROFILE-001", item.evidence_key),
        finding_type="Public Profile",
        title=f"Public Profile Discovered on {platform}",
        description=f"A publicly accessible profile corresponding to this username was located on {platform}.",
        evidence=url if url else f"Platform: {platform}",
        severity="Info",
        status="Informational",
        category="Observation",
        rule_id="USR-PROFILE-001",
        limitations="A matching username on a public platform does not verify identity, ownership, or affiliation."
    )

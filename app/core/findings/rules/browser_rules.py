from typing import Optional
from app.models.common import Finding
from app.core.findings.models import NormalizedCheckResult, EvidenceItem, make_finding_id

def rule_brw_profile_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    BRW-PROFILE-001: Browser or profile information detected.
    Category: Observation
    Severity: Info
    Status: Informational
    """
    if item.source_module != "browser" or item.item_type != "browser_profile":
        return None

    b_name = item.properties.get("browser_name", "Browser")
    profile = item.properties.get("profile", "Default")
    exe = item.properties.get("executable_path")

    evidence_text = f"Browser: {b_name} | Profile: {profile}"
    if exe:
        evidence_text += f" | Path: {exe}"

    return Finding(
        finding_id=make_finding_id("BRW-PROFILE-001", item.evidence_key),
        finding_type="Browser Profile",
        title=f"Browser Profile Detected: {b_name} ({profile})",
        description=f"Local browser profile configuration discovered for '{b_name}'.",
        evidence=evidence_text,
        severity="Info",
        status="Informational",
        category="Observation",
        rule_id="BRW-PROFILE-001",
        limitations="Browser profile presence is standard local application configuration and does not indicate tracking, a breach, or public exposure."
    )

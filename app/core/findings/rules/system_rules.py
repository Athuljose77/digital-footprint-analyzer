from typing import Optional
from app.models.common import Finding
from app.core.findings.models import NormalizedCheckResult, EvidenceItem, make_finding_id

def rule_sys_startup_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    SYS-STARTUP-001: Detected startup application.
    Category: Observation
    Severity: Info
    Status: Informational
    """
    if item.source_module != "system" or item.item_type != "startup_app":
        return None

    app_name = item.properties.get("name", "Unknown Application")
    cmd = item.properties.get("command", "Unavailable")
    scope = item.properties.get("scope", "system")

    return Finding(
        finding_id=make_finding_id("SYS-STARTUP-001", item.evidence_key),
        finding_type="Startup Application",
        title=f"Startup Application Configured: {app_name}",
        description=f"'{app_name}' is configured to run automatically on system boot or login (scope: {scope}).",
        evidence=cmd if cmd != "Unavailable" else f"App: {app_name}",
        severity="Info",
        status="Informational",
        category="Observation",
        rule_id="SYS-STARTUP-001",
        limitations="Automatic startup is standard operating system functionality and does not indicate malicious activity."
    )

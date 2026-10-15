from typing import Optional
from app.models.common import Finding
from app.core.findings.models import NormalizedCheckResult, EvidenceItem, make_finding_id

def rule_eml_breach_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    EML-BREACH-001: Breach record check.
    - If verified: Concern, severity High, status Unremediated.
    - If unconfirmed/unverified: Observation, severity Info, status Informational.
    """
    if item.source_module != "email" or item.item_type != "email_breach":
        return None

    name = item.properties.get("breach_name", "Unknown Breach")
    records = item.properties.get("records_exposed", "Unknown")
    is_verified = item.properties.get("verified", False)
    pwd_risk = item.properties.get("password_risk", False)
    exposed_data = item.properties.get("exposed_data") or []

    data_summary = ", ".join(exposed_data) if exposed_data else "Account records"

    if is_verified:
        pwd_note = " Password exposure indicated." if pwd_risk else ""
        return Finding(
            finding_id=make_finding_id("EML-BREACH-001", item.evidence_key),
            finding_type="Email Breach",
            title=f"Confirmed Breach Exposure: {name}",
            description=f"Email identified in verified {name} breach ({records} records exposed). Exposed fields: {data_summary}.{pwd_note}",
            evidence=exposed_data if exposed_data else [f"Breach: {name}"],
            severity="High",
            status="Unremediated",
            category="Concern",
            rule_id="EML-BREACH-001",
            limitations="Breach records reflect historical external exposure; this does not prove active compromise of current credentials."
        )

    # If not confirmed / unverified by service
    return Finding(
        finding_id=make_finding_id("EML-BREACH-001", item.evidence_key),
        finding_type="Email Breach Record",
        title=f"Unconfirmed Breach Record: {name}",
        description=f"Email referenced in unconfirmed record for {name} ({records} records exposed).",
        evidence=exposed_data if exposed_data else [f"Breach: {name}"],
        severity="Info",
        status="Informational",
        category="Observation",
        rule_id="EML-BREACH-001",
        limitations="Record is listed as unverified by the breach intelligence provider and does not establish verified exposure."
    )

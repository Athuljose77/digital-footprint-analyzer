from typing import Optional
from app.models.common import Finding
from app.core.findings.models import NormalizedCheckResult, EvidenceItem, make_finding_id

def rule_file_gps_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    FILE-GPS-001: GPS metadata detected.
    Category: Concern
    Severity: Medium
    Status: Unremediated
    """
    if item.source_module != "file_metadata" or item.item_type != "gps_metadata":
        return None

    field = item.properties.get("field", "GPS Coordinates")
    val = item.properties.get("value", "")

    return Finding(
        finding_id=make_finding_id("FILE-GPS-001", item.evidence_key),
        finding_type="Embedded Geolocation",
        title="Embedded GPS Location Data Detected",
        description=f"The analyzed file contains embedded geographic location coordinates ({field}).",
        evidence=str(val) if val else f"Field: {field}",
        severity="Medium",
        status="Unremediated",
        category="Concern",
        rule_id="FILE-GPS-001",
        limitations="Location metadata exists in the selected local file; this does not establish that the file has been transmitted or published online."
    )


def rule_file_camera_001(result: NormalizedCheckResult, item: EvidenceItem) -> Optional[Finding]:
    """
    FILE-CAMERA-001: Camera/device metadata detected.
    Category: Observation
    Severity: Info
    Status: Informational
    """
    if item.source_module != "file_metadata" or item.item_type != "camera_metadata":
        return None

    field = item.properties.get("field", "Device Information")
    val = item.properties.get("value", "")
    desc = item.properties.get("description", "hardware or software details")

    f_lower = str(field).lower()
    if "lens" in f_lower:
        title = f"Lens Hardware Detected: {field}"
    elif "model" in f_lower:
        title = f"Camera/Device Model Detected: {field}"
    elif "make" in f_lower:
        title = f"Camera Manufacturer Detected: {field}"
    elif "serial" in f_lower:
        title = f"Device Serial Number Detected: {field}"
    elif "software" in f_lower:
        title = f"Software/Firmware Detected: {field}"
    elif any(k in f_lower for k in ["owner", "artist", "author"]):
        title = f"Author/Owner Metadata Detected: {field}"
    else:
        title = f"Device/Camera Metadata Detected: {field}"

    return Finding(
        finding_id=make_finding_id("FILE-CAMERA-001", item.evidence_key),
        finding_type="Device Metadata",
        title=title,
        description=f"The analyzed file contains embedded device metadata ({desc}).",
        evidence=str(val) if val else f"Field: {field}",
        severity="Info",
        status="Informational",
        category="Observation",
        rule_id="FILE-CAMERA-001",
        limitations="Device metadata is standard image metadata recorded by hardware/software and does not indicate malicious tampering or unauthorized exposure."
    )

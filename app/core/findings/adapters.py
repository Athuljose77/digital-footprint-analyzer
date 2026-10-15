from typing import Dict, Any, List
from app.core.findings.models import NormalizedCheckResult, EvidenceItem

def adapt_email_result(data: Dict[str, Any]) -> NormalizedCheckResult:
    """
    Normalizes XposedOrNot email breach results.
    - Status 'ERROR' or 'UNAVAILABLE': FAILED / UNKNOWN
    - Status 'SUCCESS' with 0 breaches: COMPLETED / NOT_FOUND
    - Status 'SUCCESS' with 1+ breaches: COMPLETED / FOUND
    """
    status = data.get("status")
    if status in ("ERROR", "UNAVAILABLE"):
        err_msg = data.get("message", "Email check failed.")
        return NormalizedCheckResult(
            module="email",
            status="FAILED",
            outcome="UNKNOWN",
            errors=[err_msg],
            limitations=["Breach database check could not be completed; cannot verify presence of exposures."]
        )

    if status == "SUCCESS":
        breaches = data.get("breaches", [])
        if not breaches:
            return NormalizedCheckResult(
                module="email",
                status="COMPLETED",
                outcome="NOT_FOUND",
                evidence_items=[],
                message="No known breaches found."
            )

        items: List[EvidenceItem] = []
        for b in breaches:
            name = str(b.get("name") or "Unknown Breach").strip()
            records = b.get("records_exposed")
            date = b.get("breach_date")
            industry = b.get("industry")
            pwd_risk = b.get("password_risk")
            verified = b.get("verified")
            exposed_data = b.get("exposed_data") or []

            clean_name = name.lower().replace(" ", "_")
            evidence_key = f"email:breach:{clean_name}"

            items.append(EvidenceItem(
                source_module="email",
                item_type="email_breach",
                label=f"Breach: {name}",
                properties={
                    "breach_name": name,
                    "records_exposed": records,
                    "breach_date": date,
                    "industry": industry,
                    "password_risk": bool(pwd_risk) if pwd_risk is not None else False,
                    "verified": bool(verified) if verified is not None else False,
                    "exposed_data": exposed_data,
                },
                source="XposedOrNot",
                evidence_key=evidence_key
            ))

        return NormalizedCheckResult(
            module="email",
            status="COMPLETED",
            outcome="FOUND",
            evidence_items=items,
            message=f"Found {len(items)} breach record(s)."
        )

    return NormalizedCheckResult(
        module="email",
        status="FAILED",
        outcome="UNKNOWN",
        errors=[f"Unexpected status from email service: {status}"]
    )


def adapt_username_result(data: Dict[str, Any]) -> NormalizedCheckResult:
    """
    Normalizes Sherlock username lookup results.
    - Status 'ERROR' or 'UNKNOWN': FAILED / UNKNOWN
    - Status 'NOT_FOUND': COMPLETED / NOT_FOUND
    - Status 'FOUND': COMPLETED / FOUND
    """
    status = data.get("status")
    if status == "ERROR":
        return NormalizedCheckResult(
            module="username",
            status="FAILED",
            outcome="UNKNOWN",
            errors=[data.get("message", "Username search failed.")]
        )

    if status == "UNKNOWN":
        return NormalizedCheckResult(
            module="username",
            status="FAILED",
            outcome="UNKNOWN",
            errors=[data.get("message", "Sherlock search timed out.")],
            limitations=["Search aborted before full completion; cannot confirm absence of profiles."]
        )

    if status == "NOT_FOUND":
        return NormalizedCheckResult(
            module="username",
            status="COMPLETED",
            outcome="NOT_FOUND",
            evidence_items=[],
            message="No public profiles found for this username."
        )

    if status == "FOUND":
        results = data.get("results", [])
        items: List[EvidenceItem] = []
        for r in results:
            platform = str(r.get("platform") or "Unknown").strip()
            profile_url = str(r.get("profile_url") or "").strip()
            clean_platform = platform.lower().replace(" ", "_")
            clean_url = profile_url.lower().rstrip("/")
            evidence_key = f"username:profile:{clean_platform}:{clean_url}"

            items.append(EvidenceItem(
                source_module="username",
                item_type="social_profile",
                label=f"{platform} Profile",
                properties={
                    "platform": platform,
                    "profile_url": profile_url
                },
                source="Sherlock",
                evidence_key=evidence_key
            ))

        return NormalizedCheckResult(
            module="username",
            status="COMPLETED",
            outcome="FOUND",
            evidence_items=items,
            limitations=["Matching username does not verify account ownership."],
            message=f"Found {len(items)} public profile(s)."
        )

    return NormalizedCheckResult(
        module="username",
        status="FAILED",
        outcome="UNKNOWN",
        errors=[f"Unexpected status from username service: {status}"]
    )


def adapt_system_result(data: Dict[str, Any]) -> NormalizedCheckResult:
    """
    Normalizes read-only system footprint results, focusing on startup applications.
    """
    if data.get("status") != "SUCCESS":
        return NormalizedCheckResult(
            module="system",
            status="FAILED",
            outcome="UNKNOWN",
            errors=[data.get("message", "System scan failed.")]
        )

    res = data.get("results", {})
    startup_status = res.get("startup_applications_status", "UNAVAILABLE")
    startups = res.get("startup_applications", [])
    coverage = res.get("startup_applications_coverage", "")

    items: List[EvidenceItem] = []
    warnings: List[str] = []
    limitations: List[str] = []

    if startups:
        for app in startups:
            name = str(app.get("name") or "Unknown Application").strip()
            cmd = str(app.get("command") or "Unavailable").strip()
            src = str(app.get("source") or "System").strip()
            scope = str(app.get("scope") or "Unknown").strip()
            enabled = app.get("enabled", True)

            clean_name = name.lower().replace(" ", "_")
            clean_cmd = cmd.lower().replace(" ", "_")
            evidence_key = f"system:startup:{clean_name}:{clean_cmd}"

            items.append(EvidenceItem(
                source_module="system",
                item_type="startup_app",
                label=f"Startup Application: {name}",
                properties={
                    "name": name,
                    "command": cmd,
                    "source": src,
                    "scope": scope,
                    "enabled": enabled
                },
                source=src,
                evidence_key=evidence_key
            ))

        return NormalizedCheckResult(
            module="system",
            status="COMPLETED",
            outcome="FOUND",
            evidence_items=items,
            message=f"Detected {len(items)} startup application(s)."
        )

    if startup_status == "SUCCESS":
        return NormalizedCheckResult(
            module="system",
            status="COMPLETED",
            outcome="NOT_FOUND",
            evidence_items=[],
            message="No startup applications detected from supported sources."
        )

    # startup_status is UNAVAILABLE or partial
    warnings.append("Startup application discovery is unavailable on this platform/configuration.")
    if coverage:
        warnings.append(coverage)
    limitations.append("Could not inspect startup applications due to platform or permission constraints.")

    return NormalizedCheckResult(
        module="system",
        status="PARTIAL",
        outcome="UNKNOWN",
        evidence_items=[],
        warnings=warnings,
        limitations=limitations,
        message="System scan completed with limitations (startup applications unavailable)."
    )


def adapt_file_metadata_result(data: Dict[str, Any]) -> NormalizedCheckResult:
    """
    Normalizes file metadata inspection results (GPS location, camera/device metadata).
    """
    if data.get("status") == "ERROR":
        return NormalizedCheckResult(
            module="file_metadata",
            status="FAILED",
            outcome="UNKNOWN",
            errors=[data.get("message", "File metadata analysis error.")]
        )

    if data.get("status") == "SUCCESS":
        res = data.get("results", {})
        is_supported = res.get("is_supported", False)

        if not is_supported:
            return NormalizedCheckResult(
                module="file_metadata",
                status="COMPLETED",
                outcome="UNKNOWN",
                evidence_items=[],
                limitations=["File format is unsupported for embedded metadata analysis in v1."],
                message=data.get("message", "Unsupported file format.")
            )

        sensitive = res.get("potentially_sensitive", [])
        items: List[EvidenceItem] = []

        coord_items = []
        other_items = []

        for s in sensitive:
            cat = str(s.get("category") or "")
            field = str(s.get("field") or "")
            clean_field = field.lower().replace(" ", "_")
            is_gps = "location" in cat.lower() or "gps" in cat.lower() or "gps" in clean_field

            if is_gps and any(k in clean_field for k in ["coordinate", "latitude", "longitude"]):
                coord_items.append(s)
            else:
                other_items.append(s)

        if coord_items:
            coords_item = next((item for item in coord_items if "coordinate" in str(item.get("field", "")).lower()), None)
            lat_item = next((item for item in coord_items if "latitude" in str(item.get("field", "")).lower()), None)
            lon_item = next((item for item in coord_items if "longitude" in str(item.get("field", "")).lower()), None)

            if coords_item and coords_item.get("value"):
                combined_val = coords_item["value"]
                field_label = coords_item.get("field", "GPS Coordinates")
                desc = coords_item.get("description", "Embedded geographic location coordinates")
                cat_label = coords_item.get("category", "Location & GPS")
            elif lat_item and lon_item and lat_item.get("value") and lon_item.get("value"):
                combined_val = f"{lat_item['value']}, {lon_item['value']}"
                field_label = "GPS Coordinates"
                desc = "Embedded geographic location coordinates"
                cat_label = lat_item.get("category", "Location & GPS")
            elif lat_item and lat_item.get("value"):
                combined_val = lat_item["value"]
                field_label = lat_item.get("field", "GPS Latitude")
                desc = lat_item.get("description", "Embedded geographic latitude")
                cat_label = lat_item.get("category", "Location & GPS")
            elif lon_item and lon_item.get("value"):
                combined_val = lon_item["value"]
                field_label = lon_item.get("field", "GPS Longitude")
                desc = lon_item.get("description", "Embedded geographic longitude")
                cat_label = lon_item.get("category", "Location & GPS")
            else:
                first = coord_items[0]
                combined_val = first.get("value")
                field_label = first.get("field", "GPS Coordinates")
                desc = first.get("description", "Embedded geographic coordinates")
                cat_label = first.get("category", "Location & GPS")

            items.append(EvidenceItem(
                source_module="file_metadata",
                item_type="gps_metadata",
                label=f"GPS Metadata: {field_label}",
                properties={
                    "category": cat_label,
                    "field": field_label,
                    "value": combined_val,
                    "description": desc
                },
                source="Exif GPS SubIFD",
                evidence_key="file_metadata:gps:location"
            ))

        for s in other_items:
            cat = str(s.get("category") or "")
            field = str(s.get("field") or "")
            val = s.get("value")
            desc = str(s.get("description") or "")
            clean_field = field.lower().replace(" ", "_")

            if "Location" in cat or "GPS" in cat or "gps" in clean_field:
                evidence_key = f"file_metadata:gps:{clean_field}"
                items.append(EvidenceItem(
                    source_module="file_metadata",
                    item_type="gps_metadata",
                    label=f"GPS Metadata: {field}",
                    properties={
                        "category": cat,
                        "field": field,
                        "value": val,
                        "description": desc
                    },
                    source="Exif GPS SubIFD",
                    evidence_key=evidence_key
                ))
            elif "Camera" in cat or "Device" in cat or any(k in clean_field for k in ["model", "make", "software", "lens", "serial"]):
                evidence_key = f"file_metadata:camera:{clean_field}"
                items.append(EvidenceItem(
                    source_module="file_metadata",
                    item_type="camera_metadata",
                    label=f"Camera/Device Metadata: {field}",
                    properties={
                        "category": cat,
                        "field": field,
                        "value": val,
                        "description": desc
                    },
                    source="Exif/Device Tag",
                    evidence_key=evidence_key
                ))

        outcome = "FOUND" if items else "NOT_FOUND"
        return NormalizedCheckResult(
            module="file_metadata",
            status="COMPLETED",
            outcome=outcome,
            evidence_items=items,
            message=data.get("message", "Metadata inspection completed.")
        )

    return NormalizedCheckResult(
        module="file_metadata",
        status="FAILED",
        outcome="UNKNOWN",
        errors=[f"Unexpected status from file metadata service: {data.get('status')}"]
    )


def adapt_browser_result(data: Dict[str, Any]) -> NormalizedCheckResult:
    """
    Normalizes browser footprint detection results (browsers and local profiles).
    """
    raw_status = data.get("status", "UNAVAILABLE")
    browsers = data.get("browsers", [])
    unavail = data.get("unavailable_sources", [])
    errors = data.get("errors", [])

    if raw_status == "UNAVAILABLE":
        return NormalizedCheckResult(
            module="browser",
            status="UNAVAILABLE",
            outcome="UNKNOWN",
            errors=errors,
            limitations=unavail if unavail else ["Browser footprint scanning is not supported on this platform."],
            message="Browser footprint scanning is unavailable."
        )

    exec_status = "COMPLETED" if raw_status == "SUCCESS" else "PARTIAL"
    items: List[EvidenceItem] = []

    for b in browsers:
        b_name = str(b.get("name") or "Unknown Browser").strip()
        b_ver = b.get("version")
        b_exe = b.get("executable_path")
        profiles = b.get("profiles", [])
        src = str(b.get("detection_source") or "Unknown").strip()
        clean_b = b_name.lower().replace(" ", "_")

        if profiles:
            for p in profiles:
                clean_p = str(p).lower().replace(" ", "_")
                evidence_key = f"browser:profile:{clean_b}:{clean_p}"
                items.append(EvidenceItem(
                    source_module="browser",
                    item_type="browser_profile",
                    label=f"{b_name} Profile ({p})",
                    properties={
                        "browser_name": b_name,
                        "version": b_ver,
                        "profile": str(p),
                        "executable_path": b_exe
                    },
                    source=src,
                    evidence_key=evidence_key
                ))
        else:
            evidence_key = f"browser:installation:{clean_b}"
            items.append(EvidenceItem(
                source_module="browser",
                item_type="browser_profile",
                label=f"Browser: {b_name}",
                properties={
                    "browser_name": b_name,
                    "version": b_ver,
                    "profile": "Default",
                    "executable_path": b_exe
                },
                source=src,
                evidence_key=evidence_key
            ))

    outcome = "FOUND" if items else "NOT_FOUND"
    return NormalizedCheckResult(
        module="browser",
        status=exec_status,
        outcome=outcome,
        evidence_items=items,
        warnings=errors,
        limitations=unavail,
        message=f"Browser scan normalized with {len(items)} profile/browser item(s)."
    )

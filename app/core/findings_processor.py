import uuid
import copy
from typing import Dict, List, Optional, Any, Union

from app.models.common import ScanResult, FootprintData, Finding, Risk, Recommendation


# Standard severity ranking for comparison and preservation
SEVERITY_RANKS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "INFORMATIONAL": 1,
}

# Standard display casing for severities
SEVERITY_DISPLAY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "INFORMATIONAL": "Info",
}


def _get_severity_rank(sev: Optional[str]) -> int:
    """Return numeric rank for severity comparison."""
    if not sev or not isinstance(sev, str):
        return 0
    return SEVERITY_RANKS.get(sev.strip().upper(), 0)


def _normalize_severity_name(sev: Optional[str]) -> str:
    """Normalize severity string to standard capitalized name."""
    if not sev or not isinstance(sev, str):
        return "Info"
    return SEVERITY_DISPLAY.get(sev.strip().upper(), sev.strip().capitalize())


def _merge_evidence(ev1: Any, ev2: Any) -> Any:
    """
    Merge two evidence items safely without duplicating existing elements.
    Preserves item ordering.
    """
    if ev1 is None:
        return copy.deepcopy(ev2)
    if ev2 is None:
        return copy.deepcopy(ev1)

    merged_items: List[Any] = []
    seen: set = set()

    for container in (ev1, ev2):
        if isinstance(container, list):
            for item in container:
                item_key = str(item)
                if item_key not in seen:
                    seen.add(item_key)
                    merged_items.append(item)
        elif isinstance(container, (set, tuple)):
            for item in container:
                item_key = str(item)
                if item_key not in seen:
                    seen.add(item_key)
                    merged_items.append(item)
        elif isinstance(container, dict):
            item_key = str(container)
            if item_key not in seen:
                seen.add(item_key)
                merged_items.append(container)
        else:
            item_key = str(container)
            if item_key not in seen:
                seen.add(item_key)
                merged_items.append(container)

    return merged_items if merged_items else ev1


class FindingsProcessor:
    """
    Central processor for normalizing, deduplicating, and synthesizing
    digital footprint findings across all scanning modules.
    """

    @classmethod
    def normalize_finding(cls, item: Union[Finding, Dict[str, Any]]) -> Finding:
        """
        Normalize a finding object or dictionary into a standard, validated Finding instance.
        Handles missing fields safely with sane defaults.
        """
        if isinstance(item, Finding):
            finding_id = item.finding_id or str(uuid.uuid4())
            finding_type = item.finding_type.strip() if item.finding_type else "General"
            title = item.title.strip() if item.title else "Untitled Finding"
            description = item.description.strip() if item.description else ""
            severity = _normalize_severity_name(item.severity)
            status = item.status.strip().capitalize() if item.status else "Active"
            evidence = copy.deepcopy(item.evidence)

            return Finding(
                finding_id=finding_id,
                finding_type=finding_type,
                title=title,
                description=description,
                evidence=evidence,
                severity=severity,
                status=status
            )

        if isinstance(item, dict):
            finding_id = str(item.get("finding_id") or uuid.uuid4())
            finding_type = str(item.get("finding_type") or "General").strip()
            title = str(item.get("title") or "Untitled Finding").strip()
            description = str(item.get("description") or "").strip()
            severity = _normalize_severity_name(item.get("severity"))
            raw_status = str(item.get("status") or "Active").strip()
            status = raw_status.capitalize() if raw_status else "Active"
            evidence = copy.deepcopy(item.get("evidence"))

            return Finding(
                finding_id=finding_id,
                finding_type=finding_type,
                title=title,
                description=description,
                evidence=evidence,
                severity=severity,
                status=status
            )

        # Fallback for unexpected data types
        return Finding(
            finding_id=str(uuid.uuid4()),
            finding_type="Unknown",
            title=str(item),
            description="Normalized from unexpected data type.",
            evidence=None,
            severity="Info",
            status="Informational"
        )

    @classmethod
    def deduplicate_findings(cls, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicates findings using (finding_type, title) as a sensible identity key.
        - Preserves the first-seen insertion order.
        - Merges evidence elements without duplication.
        - Retains the highest severity among duplicates.
        - Retains the more descriptive content.
        - Retains actionable status over informational status.
        """
        if not findings:
            return []

        dedup_map: Dict[str, Finding] = {}
        order: List[str] = []

        for raw_finding in findings:
            if not raw_finding:
                continue

            f = cls.normalize_finding(raw_finding)
            key = f"{f.finding_type.strip().lower()}::{f.title.strip().lower()}"

            if key not in dedup_map:
                dedup_map[key] = f
                order.append(key)
            else:
                existing = dedup_map[key]

                # 1. Preserve highest severity
                current_rank = _get_severity_rank(existing.severity)
                new_rank = _get_severity_rank(f.severity)
                chosen_severity = existing.severity if current_rank >= new_rank else f.severity

                # 2. Merge evidence
                merged_evidence = _merge_evidence(existing.evidence, f.evidence)

                # 3. Preserve longer/richer description
                chosen_desc = existing.description
                if f.description and len(f.description) > len(existing.description or ""):
                    chosen_desc = f.description

                # 4. Status prioritization: prefer active/unremediated over informational
                status_priority = {
                    "UNREMEDIATED": 4,
                    "ACTIVE": 3,
                    "OPEN": 3,
                    "WARNING": 2,
                    "INFORMATIONAL": 1,
                    "INFO": 1,
                    "RESOLVED": 0
                }
                curr_st_rank = status_priority.get(existing.status.upper(), 1)
                new_st_rank = status_priority.get(f.status.upper(), 1)
                chosen_status = existing.status if curr_st_rank >= new_st_rank else f.status

                dedup_map[key] = Finding(
                    finding_id=existing.finding_id,
                    finding_type=existing.finding_type,
                    title=existing.title,
                    description=chosen_desc,
                    evidence=merged_evidence,
                    severity=chosen_severity,
                    status=chosen_status
                )

        return [dedup_map[k] for k in order]

    @classmethod
    def extract_module_findings(cls, module_name: str, scan_res: Any) -> List[Finding]:
        """
        Extracts and converts supported findings from an individual scan module result.
        Handles both ScanResult instances and raw service result dictionaries.
        Does NOT invent findings; generates them only when supported by evidence.
        """
        if scan_res is None:
            return []

        findings: List[Finding] = []
        mod_lower = module_name.strip().lower() if isinstance(module_name, str) else ""

        # Case 1: Result is a ScanResult
        if isinstance(scan_res, ScanResult):
            # Include any pre-existing findings attached to the ScanResult
            for f in scan_res.findings:
                findings.append(cls.normalize_finding(f))

            # Inspect footprint_data for modules that only populated footprint_data
            cls._extract_from_footprint_data(mod_lower, scan_res.footprint_data, findings)
            return cls.deduplicate_findings(findings)

        # Case 2: Result is a raw dictionary (e.g. directly from a service function)
        if isinstance(scan_res, dict):
            # If dictionary already contains a 'findings' list
            if "findings" in scan_res and isinstance(scan_res["findings"], list):
                for f in scan_res["findings"]:
                    findings.append(cls.normalize_finding(f))

            # Email service dictionary
            if mod_lower in ("email", "email exposure") or "breaches" in scan_res:
                cls._extract_email_dict_findings(scan_res, findings)

            # Username service dictionary
            elif mod_lower in ("username", "public presence") or ("results" in scan_res and scan_res.get("type") == "username"):
                cls._extract_username_dict_findings(scan_res, findings)

            # System service dictionary
            elif mod_lower in ("system", "system footprint") or ("results" in scan_res and "installed_applications" in scan_res.get("results", {})):
                cls._extract_system_dict_findings(scan_res, findings)

            # File metadata service dictionary
            elif mod_lower in ("file & metadata", "file metadata", "file") or ("results" in scan_res and "potentially_sensitive" in scan_res.get("results", {})):
                cls._extract_file_dict_findings(scan_res, findings)

            # Browser service dictionary
            elif mod_lower in ("browser", "browser footprint") or "browsers" in scan_res:
                cls._extract_browser_dict_findings(scan_res, findings)

            return cls.deduplicate_findings(findings)

        return findings

    @classmethod
    def _extract_from_footprint_data(cls, mod_name: str, footprint_data: List[FootprintData], findings: List[Finding]) -> None:
        """Extract findings from structured FootprintData items."""
        if not footprint_data:
            return

        # 1. Username / Public Presence
        if "username" in mod_name or "public" in mod_name:
            profiles = [fd for fd in footprint_data if fd.subcategory == "Social Profile" or fd.category == "Public Presence"]
            if profiles:
                platforms = [p.source for p in profiles if p.source and p.source != "Unknown"]
                urls = [str(p.value) for p in profiles if p.value]
                count = len(profiles)

                platforms_summary = ", ".join(platforms[:8])
                if len(platforms) > 8:
                    platforms_summary += f", and {len(platforms) - 8} more"

                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Public Presence",
                    title="Possible username matches — ownership unverified",
                    description=(
                        f"Public profiles matching this username were detected across {count} platform(s): {platforms_summary}. "
                        "Ownership is unverified; these accounts may belong to different individuals using the same handle."
                    ),
                    evidence=urls,
                    severity="Info",
                    status="Informational"
                ))

        # 2. File & Metadata
        if "file" in mod_name or "metadata" in mod_name:
            sensitive = [fd for fd in footprint_data if fd.subcategory == "Potentially Sensitive"]
            for s in sensitive:
                val_str = str(s.value)
                source_cat = str(s.source)

                if "Location" in source_cat or "GPS" in source_cat:
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type="Sensitive Metadata",
                        title="Location Metadata Detected in File",
                        description=f"Geographic coordinates or location metadata found: {val_str}",
                        evidence=[val_str],
                        severity="High",
                        status="Unremediated"
                    ))
                elif any(k in source_cat for k in ("Device", "Personal", "Hardware", "Identification")):
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type="Sensitive Metadata",
                        title=f"Personal or Device Metadata Detected ({source_cat})",
                        description=f"File contains identifier details: {val_str}",
                        evidence=[val_str],
                        severity="Medium",
                        status="Unremediated"
                    ))
                else:
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type="Sensitive Metadata",
                        title=f"Embedded Metadata Detected ({source_cat})",
                        description=f"File contains technical metadata: {val_str}",
                        evidence=[val_str],
                        severity="Low",
                        status="Informational"
                    ))

        # 3. System Footprint
        if "system" in mod_name:
            startup_apps = [
                fd for fd in footprint_data
                if fd.subcategory == "Startup Applications" and "Unavailable" not in str(fd.value) and "No startup" not in str(fd.value)
            ]
            if startup_apps:
                app_names = [str(a.value) for a in startup_apps]
                sev = "Medium" if len(startup_apps) >= 15 else "Low"
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="System Configuration",
                    title=f"Persistent Startup Footprint ({len(startup_apps)} detected)",
                    description="Applications configured to start automatically on system boot were detected.",
                    evidence=app_names,
                    severity=sev,
                    status="Informational"
                ))

    @classmethod
    def _extract_email_dict_findings(cls, data: Dict[str, Any], findings: List[Finding]) -> None:
        """Extract findings from an email breach dictionary."""
        breaches = data.get("breaches", [])
        for b in breaches:
            if not isinstance(b, dict):
                continue
            name = b.get("name", "Unknown Breach")
            records = b.get("records_exposed", "Unknown")
            industry = b.get("industry", "Unknown")
            exposed = b.get("exposed_data", [])
            has_pw = bool(b.get("password_risk"))

            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Email Breach",
                title=f"Exposed in {name}",
                description=f"Records exposed: {records}. Industry: {industry}",
                evidence=exposed if isinstance(exposed, list) else [str(exposed)],
                severity="High" if has_pw else "Medium",
                status="Unremediated"
            ))

    @classmethod
    def _extract_username_dict_findings(cls, data: Dict[str, Any], findings: List[Finding]) -> None:
        """Extract findings from a username profile dictionary."""
        results = data.get("results", [])
        if results and isinstance(results, list):
            platforms = [r.get("platform", "Unknown") for r in results if isinstance(r, dict)]
            urls = [r.get("profile_url", "") for r in results if isinstance(r, dict) and r.get("profile_url")]
            count = len(results)

            platforms_str = ", ".join(platforms[:8])
            if len(platforms) > 8:
                platforms_str += f", and {len(platforms) - 8} more"

            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Public Presence",
                title="Possible username matches — ownership unverified",
                description=(
                    f"Public profiles matching this username were detected across {count} platform(s): {platforms_str}. "
                    "Ownership is unverified; these accounts may belong to different individuals using the same handle."
                ),
                evidence=urls,
                severity="Info",
                status="Informational"
            ))

    @classmethod
    def _extract_system_dict_findings(cls, data: Dict[str, Any], findings: List[Finding]) -> None:
        """Extract findings from a system scanner dictionary."""
        sys_res = data.get("results", {}) if isinstance(data.get("results"), dict) else data
        startups = sys_res.get("startup_applications", [])
        if startups and isinstance(startups, list):
            names = [s.get("name", "Unknown") for s in startups if isinstance(s, dict)]
            sev = "Medium" if len(startups) >= 15 else "Low"
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="System Configuration",
                title=f"Persistent Startup Footprint ({len(startups)} detected)",
                description="Applications configured to start automatically on system boot were detected.",
                evidence=names,
                severity=sev,
                status="Informational"
            ))

    @classmethod
    def _extract_file_dict_findings(cls, data: Dict[str, Any], findings: List[Finding]) -> None:
        """Extract findings from a file metadata dictionary."""
        res = data.get("results", {}) if isinstance(data.get("results"), dict) else data
        sensitive = res.get("potentially_sensitive", [])
        for s in sensitive:
            if not isinstance(s, dict):
                continue
            cat = s.get("category", "")
            field = s.get("field", "")
            val = s.get("value", "")
            desc = s.get("description", "")
            line = f"[{cat}] {field}: {val} — {desc}"

            if "Location" in cat or "GPS" in cat:
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Sensitive Metadata",
                    title="Location Metadata Detected in File",
                    description=desc or "File contains GPS geographic location metadata.",
                    evidence=[line],
                    severity="High",
                    status="Unremediated"
                ))
            elif any(k in cat for k in ("Device", "Personal", "Hardware", "Identification")):
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Sensitive Metadata",
                    title=f"Personal or Device Metadata Detected ({cat})",
                    description=desc or "File metadata reveals personal or device identification.",
                    evidence=[line],
                    severity="Medium",
                    status="Unremediated"
                ))
            else:
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Sensitive Metadata",
                    title=f"Embedded Metadata Detected ({cat})",
                    description=desc or "File metadata detected.",
                    evidence=[line],
                    severity="Low",
                    status="Informational"
                ))

    @classmethod
    def _extract_browser_dict_findings(cls, data: Dict[str, Any], findings: List[Finding]) -> None:
        """Extract findings from a browser scan dictionary."""
        coverage = data.get("coverage", {})
        errors = data.get("errors", [])
        failed_sources = coverage.get("sources_failed", [])

        if coverage:
            searched = coverage.get("browsers_searched", [])
            detected = coverage.get("browsers_detected", [])
            cov_desc = f"Browsers searched: {', '.join(searched)}; Detected: {', '.join(detected)}"
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Scan Coverage",
                title="Browser Footprint Scan Coverage",
                description=cov_desc,
                evidence=coverage,
                severity="Info",
                status="Informational"
            ))

        if failed_sources:
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Unavailable Sources",
                title="Sources That Could Not Be Checked",
                description=" | ".join(failed_sources),
                evidence=failed_sources,
                severity="Info",
                status="Informational"
            ))

        if errors:
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Scan Warnings",
                title="Non-Fatal Scan Warnings",
                description=f"{len(errors)} warning(s) encountered during scan",
                evidence=errors,
                severity="Low",
                status="Informational"
            ))

    @classmethod
    def process_module_results(
        cls,
        module_results: Union[Dict[str, Any], List[Any]],
        module_errors: Optional[Dict[str, str]] = None,
        combined_scan_id: Optional[str] = None
    ) -> ScanResult:
        """
        Accepts results and errors from individual scan modules.
        Extracts, normalizes, and deduplicates findings across all modules.
        Aggregates footprint data and produces a consolidated, valid ScanResult.
        """
        scan_id = combined_scan_id or str(uuid.uuid4())
        all_findings: List[Finding] = []
        all_footprint_data: List[FootprintData] = []
        successful_modules = 0
        failed_count = 0

        # Standardize iteration over module results
        results_iterable: List[tuple] = []
        if isinstance(module_results, dict):
            for mod_name, res in module_results.items():
                results_iterable.append((str(mod_name), res))
        elif isinstance(module_results, list):
            for res in module_results:
                if isinstance(res, ScanResult):
                    results_iterable.append((res.scan_type or "Unknown", res))
                elif isinstance(res, dict):
                    results_iterable.append((str(res.get("type") or "Unknown"), res))
                else:
                    results_iterable.append(("Unknown", res))

        # Process each module result safely
        for mod_name, scan_res in results_iterable:
            try:
                if scan_res is None:
                    continue

                # Check if result indicates module error
                if isinstance(scan_res, ScanResult):
                    if scan_res.status == "ERROR":
                        failed_count += 1
                        all_findings.append(Finding(
                            finding_id=str(uuid.uuid4()),
                            finding_type="Scan Limitation",
                            title=f"Module Limitation: {mod_name.capitalize()}",
                            description=f"The {mod_name} scan encountered an issue: {scan_res.message or 'Module failed'}",
                            evidence=[scan_res.message] if scan_res.message else None,
                            severity="Info",
                            status="Limitation"
                        ))
                    else:
                        successful_modules += 1
                        all_footprint_data.extend(scan_res.footprint_data)

                    extracted = cls.extract_module_findings(mod_name, scan_res)
                    all_findings.extend(extracted)

                elif isinstance(scan_res, dict):
                    if scan_res.get("status") == "ERROR":
                        failed_count += 1
                        err_msg = scan_res.get("message", "Module scan failed.")
                        all_findings.append(Finding(
                            finding_id=str(uuid.uuid4()),
                            finding_type="Scan Limitation",
                            title=f"Module Limitation: {mod_name.capitalize()}",
                            description=f"The {mod_name} scan encountered an issue: {err_msg}",
                            evidence=[err_msg],
                            severity="Info",
                            status="Limitation"
                        ))
                    else:
                        successful_modules += 1

                    extracted = cls.extract_module_findings(mod_name, scan_res)
                    all_findings.extend(extracted)

            except Exception as e:
                # Catch any unexpected malformed module data without crashing the pipeline
                failed_count += 1
                all_findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Scan Limitation",
                    title=f"Module Processing Error: {mod_name.capitalize()}",
                    description=f"Unexpected error processing {mod_name} results: {str(e)}",
                    evidence=[str(e)],
                    severity="Low",
                    status="Limitation"
                ))

        # Process explicit module errors
        if module_errors and isinstance(module_errors, dict):
            for mod_name, err_msg in module_errors.items():
                failed_count += 1
                all_findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Scan Limitation",
                    title=f"Module Limitation: {mod_name.capitalize()}",
                    description=f"The {mod_name} scan encountered an issue: {err_msg}",
                    evidence=[err_msg],
                    severity="Info",
                    status="Limitation"
                ))

        # Deduplicate and sort findings by severity (Critical -> High -> Medium -> Low -> Info)
        deduped = cls.deduplicate_findings(all_findings)
        deduped.sort(key=lambda f: _get_severity_rank(f.severity), reverse=True)

        # Determine overall status and message
        total_modules = successful_modules + failed_count
        if total_modules > 0 and successful_modules == 0:
            status = "ERROR"
            message = "Scan completed with errors on all attempted modules."
        elif failed_count > 0:
            status = "PARTIAL" if hasattr(cls, "_allow_partial") else "COMPLETED"
            message = f"Scan completed with partial results ({successful_modules} succeeded, {failed_count} had limitations)."
        else:
            status = "COMPLETED"
            message = f"Scan completed successfully across all {successful_modules} modules."

        return ScanResult(
            scan_id=scan_id,
            analysis_mode="Full Footprint Analysis",
            scan_type="Full Scan",
            scan_category="Unified Footprint",
            status=status,
            message=message,
            footprint_data=all_footprint_data,
            findings=deduped,
            risks=[],
            recommendations=[]
        )

    @classmethod
    def process_scan_result(cls, scan_result: ScanResult) -> ScanResult:
        """
        Processes a single module's ScanResult in-place or returning a cleaned copy:
        extracts missing findings from footprint_data, normalizes, and deduplicates existing findings.
        """
        if not isinstance(scan_result, ScanResult):
            return scan_result

        combined_findings = list(scan_result.findings)
        module_name = scan_result.scan_type or scan_result.scan_category or ""

        # Extract any unmaterialized findings from footprint_data
        cls._extract_from_footprint_data(module_name.lower(), scan_result.footprint_data, combined_findings)

        # Deduplicate and sort
        deduped = cls.deduplicate_findings(combined_findings)
        deduped.sort(key=lambda f: _get_severity_rank(f.severity), reverse=True)

        scan_result.findings = deduped
        return scan_result

import uuid
import sys
import os

# Ensure backend modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app.models.common import ScanResult, FootprintData, Finding
from backend.services.email_service import check_email
from backend.services.username_service import check_username

async def run_email_scan(email: str) -> ScanResult:
    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        analysis_mode="Public Footprint Lookup",
        scan_type="Email",
        scan_category="Email Exposure",
        status="RUNNING"
    )
    
    try:
        data = await check_email(email)
        
        if data.get("status") == "ERROR":
            result.status = "ERROR"
            result.message = data.get("message", "Unknown error")
            return result
            
        if data.get("status") == "UNAVAILABLE":
            result.status = "ERROR"
            result.message = data.get("message", "Service unavailable")
            return result
        
        if data.get("status") == "SUCCESS":
            result.status = "COMPLETED"
            breaches = data.get("breaches", [])
            
            if not breaches:
                result.message = "No known breaches found."
                return result
                
            result.message = f"Found {len(breaches)} breaches."
            
            for b in breaches:
                # Normalize breach data into a Finding
                result.findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    finding_type="Email Breach",
                    title=f"Exposed in {b.get('name', 'Unknown')}",
                    description=f"Records exposed: {b.get('records_exposed', 'Unknown')}. Industry: {b.get('industry', 'Unknown')}",
                    evidence=b.get("exposed_data", []),
                    severity="High" if b.get("password_risk") else "Medium",
                    status="Unremediated"
                ))
            return result
            
        result.status = "UNKNOWN"
        result.message = "Unexpected status from email service"
        return result
        
    except Exception as e:
        result.status = "ERROR"
        result.message = str(e)
        return result


async def run_username_scan(username: str) -> ScanResult:
    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        analysis_mode="Public Footprint Lookup",
        scan_type="Username",
        scan_category="Public Presence",
        status="RUNNING"
    )
    
    try:
        data = await check_username(username)
        if data.get("status") == "ERROR":
            result.status = "ERROR"
            result.message = data.get("message", "Unknown error")
            return result
            
        if data.get("status") == "FOUND":
            result.status = "COMPLETED"
            found_list = data.get("results", [])
            result.message = f"Found {len(found_list)} profiles."
            
            for item in found_list:
                result.footprint_data.append(FootprintData(
                    category="Public Presence",
                    subcategory="Social Profile",
                    source=item.get("platform", "Unknown"),
                    data_type="URL",
                    value=item.get("profile_url"),
                    sensitivity="Low"
                ))
            return result
            
        if data.get("status") == "NOT_FOUND":
            result.status = "COMPLETED"
            result.message = "No profiles found."
            return result
            
        result.status = "UNKNOWN"
        result.message = "Unexpected status from username service"
        return result
        
    except Exception as e:
        result.status = "ERROR"
        result.message = str(e)
        return result

from app.services.system_service import check_system

async def run_system_scan() -> ScanResult:
    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        analysis_mode="My Footprint",
        scan_type="System",
        scan_category="System Footprint",
        status="RUNNING"
    )
    
    try:
        data = await check_system()
        
        if data.get("status") == "SUCCESS":
            result.status = "COMPLETED"
            sys_res = data.get("results", {})
            
            # Map collected data to FootprintData
            if "os" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="Operating System",
                    source="System API", data_type="String",
                    value=sys_res["os"], sensitivity="Low"
                ))
            if "os_version" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="OS Version",
                    source="System API", data_type="String",
                    value=sys_res["os_version"], sensitivity="Low"
                ))
            if "hostname" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="Hostname",
                    source="System API", data_type="String",
                    value=sys_res["hostname"], sensitivity="Low"
                ))
            if "cpu" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="CPU",
                    source="System API", data_type="String",
                    value=sys_res["cpu"], sensitivity="Low"
                ))
            if "memory" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="Memory",
                    source="System API", data_type="String",
                    value=sys_res["memory"], sensitivity="Low"
                ))
            if "network" in sys_res:
                result.footprint_data.append(FootprintData(
                    category="System", subcategory="Network",
                    source="System API", data_type="String",
                    value=sys_res["network"], sensitivity="Low"
                ))
                
            # 7. Installed Applications
            app_status = sys_res.get("installed_applications_status", "UNAVAILABLE")
            app_coverage = sys_res.get("installed_applications_coverage", "")
            apps = sys_res.get("installed_applications", [])

            if apps:
                for app in apps:
                    app_name = app.get("name", "Unknown Application")
                    app_ver = app.get("version")
                    val_str = f"{app_name} — version {app_ver}" if app_ver else app_name
                    result.footprint_data.append(FootprintData(
                        category="System",
                        subcategory="Installed Applications",
                        source=app.get("source", "System Package Manager"),
                        data_type="application",
                        value=val_str,
                        sensitivity="Low"
                    ))
                result.message = f"System scan completed successfully. {app_coverage}." if app_coverage else "System scan completed successfully."
            elif app_status == "UNAVAILABLE":
                result.footprint_data.append(FootprintData(
                    category="System",
                    subcategory="Installed Applications",
                    source="Local Package Database",
                    data_type="application",
                    value="Unavailable (No supported local package manager or source detected)",
                    sensitivity="Low"
                ))
                result.message = "System scan completed with limitations. Installed applications unavailable."
            else:
                result.message = "System scan completed successfully. No installed applications detected."

            # 8. Running Processes
            proc_status = sys_res.get("running_processes_status", "UNAVAILABLE")
            procs = sys_res.get("running_processes", [])
            
            if procs:
                for p in procs:
                    pid = p.get("pid", "Unknown PID")
                    name = p.get("name", "Unknown Process")
                    exe = p.get("executable", "Unavailable")
                    user = p.get("user", "Unavailable")
                    status = p.get("status", "Unavailable")
                    
                    val_str = f"PID {pid}: {name}"
                    if exe != "Unavailable":
                        val_str += f" | Path: {exe}"
                    if user != "Unavailable":
                        val_str += f" | User: {user}"
                    if status != "Unavailable":
                        val_str += f" | Status: {status}"
                        
                    result.footprint_data.append(FootprintData(
                        category="System",
                        subcategory="Running Processes",
                        source="Local OS API",
                        data_type="process",
                        value=val_str,
                        sensitivity="Low"
                    ))
            elif proc_status == "UNAVAILABLE":
                result.footprint_data.append(FootprintData(
                    category="System",
                    subcategory="Running Processes",
                    source="Local OS API",
                    data_type="process",
                    value="Unavailable (Cannot collect running processes)",
                    sensitivity="Low"
                ))

            # 9. Startup Applications
            startup_status = sys_res.get("startup_applications_status", "UNAVAILABLE")
            startups = sys_res.get("startup_applications", [])
            startup_coverage = sys_res.get("startup_applications_coverage", "")
            
            if startups:
                for app in startups:
                    name = app.get("name", "Unknown Application")
                    source = app.get("source", "Unknown Source")
                    scope = app.get("scope", "Unknown Scope")
                    cmd = app.get("command", "Unavailable")
                    enabled = app.get("enabled", "Unknown")
                    
                    val_str = f"Name: {name} | Scope: {scope}"
                    if enabled != "Unknown":
                        val_str += f" | Enabled: {enabled}"
                    if cmd != "Unavailable":
                        val_str += f" | Path: {cmd}"
                        
                    result.footprint_data.append(FootprintData(
                        category="System",
                        subcategory="Startup Applications",
                        source=source,
                        data_type="startup_application",
                        value=val_str,
                        sensitivity="Low"
                    ))
                # Optionally append the coverage info to the main message
                if result.message and startup_coverage:
                    result.message += f" {startup_coverage}"
            elif startup_status == "UNAVAILABLE":
                result.footprint_data.append(FootprintData(
                    category="System",
                    subcategory="Startup Applications",
                    source="Local OS API",
                    data_type="startup_application",
                    value="Unavailable (Cannot collect startup applications)",
                    sensitivity="Low"
                ))
            elif startup_status == "SUCCESS" and not startups:
                result.footprint_data.append(FootprintData(
                    category="System",
                    subcategory="Startup Applications",
                    source="Local OS API",
                    data_type="startup_application",
                    value="No startup applications detected from supported sources",
                    sensitivity="Low"
                ))

            return result
            
        result.status = "ERROR"
        result.message = "System scan failed."
        return result
        
    except Exception as e:
        result.status = "ERROR"
        result.message = str(e)
        return result


from app.services.browser_service import check_browsers

async def run_browser_scan() -> ScanResult:
    scan_id = str(uuid.uuid4())
    result = ScanResult(
        scan_id=scan_id,
        analysis_mode="My Footprint",
        scan_type="Browser",
        scan_category="Browser Footprint",
        status="RUNNING"
    )

    try:
        data = await check_browsers()

        if data.get("status") == "UNAVAILABLE":
            result.status = "COMPLETED"
            result.message = "Browser footprint scanning is not available on this platform."
            unavail = data.get("unavailable_sources", [])
            if unavail:
                result.footprint_data.append(FootprintData(
                    category="Browser",
                    subcategory="Scan Coverage",
                    source="Browser Footprint Service",
                    data_type="coverage",
                    value="Unavailable: " + "; ".join(unavail),
                    sensitivity="Low"
                ))
            return result

        # --- Map detected browsers to FootprintData ---
        browsers = data.get("browsers", [])
        extensions = data.get("extensions", [])
        coverage = data.get("coverage", {})
        errors = data.get("errors", [])

        for browser in browsers:
            b_name = browser.get("name", "Unknown Browser")
            b_version = browser.get("version")
            b_source = browser.get("detection_source", "Unknown")
            profiles = browser.get("profiles", [])
            ext_count = browser.get("extension_count", 0)

            val_str = b_name
            if b_version:
                val_str += f" — version {b_version}"
            val_str += f" | Profiles: {', '.join(profiles) if profiles else 'None found'}"
            val_str += f" | Extensions: {ext_count}"

            result.footprint_data.append(FootprintData(
                category="Browser",
                subcategory="Detected Browser",
                source=b_source,
                data_type="browser",
                value=val_str,
                sensitivity="Low"
            ))

        # --- Map extensions to FootprintData ---
        for ext in extensions:
            ext_name = ext.get("name", "Unknown Extension")
            ext_ver = ext.get("version")
            ext_desc = ext.get("description")
            ext_id = ext.get("extension_id", "")
            ext_browser = ext.get("browser", "Unknown")
            ext_profile = ext.get("profile", "Unknown")

            val_str = ext_name
            if ext_ver:
                val_str += f" (v{ext_ver})"
            val_str += f" | ID: {ext_id}"
            val_str += f" | Browser: {ext_browser}"
            val_str += f" | Profile: {ext_profile}"
            if ext_desc:
                val_str += f" | {ext_desc}"

            result.footprint_data.append(FootprintData(
                category="Browser",
                subcategory="Extension",
                source=f"{ext_browser} Extension Directory",
                data_type="extension",
                value=val_str,
                sensitivity="Low"
            ))

        # --- Coverage information as a Finding ---
        searched = coverage.get("browsers_searched", [])
        detected = coverage.get("browsers_detected", [])
        not_detected = coverage.get("browsers_not_detected", [])
        unsupported = coverage.get("unsupported_browsers", [])
        profiles_count = coverage.get("profiles_scanned", 0)
        ext_count = coverage.get("extensions_found", 0)
        failed_sources = coverage.get("sources_failed", [])

        coverage_parts = []
        coverage_parts.append(f"Browsers searched: {', '.join(searched) if searched else 'None'}")
        coverage_parts.append(f"Browsers detected: {', '.join(detected) if detected else 'None'}")
        if not_detected:
            coverage_parts.append(f"Not detected: {', '.join(not_detected)}")
        coverage_parts.append(f"Profiles scanned: {profiles_count}")
        coverage_parts.append(f"Extensions found: {ext_count}")
        if unsupported:
            coverage_parts.append(f"Not scanned (unsupported): {', '.join(unsupported)}")

        result.findings.append(Finding(
            finding_id=str(uuid.uuid4()),
            finding_type="Scan Coverage",
            title="Browser Footprint Scan Coverage",
            description=" | ".join(coverage_parts),
            evidence={"searched": searched, "detected": detected,
                       "not_detected": not_detected, "unsupported": unsupported},
            severity="Info",
            status="Informational"
        ))

        # --- Unavailable sources as a Finding ---
        if failed_sources:
            result.findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Unavailable Sources",
                title="Sources That Could Not Be Checked",
                description=" | ".join(failed_sources),
                evidence=failed_sources,
                severity="Info",
                status="Informational"
            ))

        # --- Non-fatal errors as a Finding ---
        if errors:
            result.findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                finding_type="Scan Warnings",
                title="Non-Fatal Scan Warnings",
                description=f"{len(errors)} warning(s) encountered during scan",
                evidence=errors,
                severity="Low",
                status="Informational"
            ))

        # --- Summary message ---
        msg_parts = []
        if browsers:
            msg_parts.append(f"{len(browsers)} browser(s) detected")
        else:
            msg_parts.append("No supported browsers detected")
        if extensions:
            msg_parts.append(f"{len(extensions)} extension(s) found")
        msg_parts.append(f"{profiles_count} profile(s) scanned")
        if unsupported:
            msg_parts.append(f"{len(unsupported)} browser(s) not scanned (unsupported)")
        result.message = "Browser scan completed. " + ". ".join(msg_parts) + "."

        result.status = "COMPLETED"
        return result

    except Exception as e:
        result.status = "ERROR"
        result.message = str(e)
        return result

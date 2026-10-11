"""
Browser Footprint Service — v1 (Windows)

Detects installed Google Chrome and Microsoft Edge browsers,
reads extension metadata from local profile directories,
and reports scan coverage and limitations.

Privacy guarantees
------------------
* Read-only: only os.path.exists, os.listdir, open(read), winreg KEY_READ.
* Never opens: History, Cookies, Login Data, Web Data, Bookmarks,
  Sessions, Favicons, or any database files.
* Never launches, modifies, or terminates browser processes.
* Never uploads data or makes network requests.
* Never requires administrator privileges.
* Does not recursively crawl the disk.
* Profile labels use folder names only (e.g. "Default", "Profile 1"),
  never user-configured display names.
"""

import json
import os
import platform
import sys
from typing import Any, Dict, List, Optional


# ============================================================
# CONSTANTS
# ============================================================

# Files that must NEVER be read — enforced as a safety net.
_SENSITIVE_FILENAMES = frozenset({
    "history", "cookies", "login data", "web data",
    "bookmarks", "sessions", "session storage",
    "favicons", "network action predictor",
    "visited links", "top sites", "shortcuts",
    "current session", "current tabs", "last session", "last tabs",
    "safe browsing", "passwords",
})

# Known Chromium profile directory prefixes.
_PROFILE_DIR_PREFIXES = ("Default", "Profile ")

# Supported browsers and their Windows-specific metadata.
_WINDOWS_BROWSERS: List[Dict[str, Any]] = [
    {
        "name": "Google Chrome",
        "registry_app_path": r"Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        "registry_version_paths": [
            (r"Software\Google\Chrome\BLBeacon", "version"),
        ],
        "user_data_env": "LOCALAPPDATA",
        "user_data_subpath": r"Google\Chrome\User Data",
        "exe_relative": r"Google\Chrome\Application\chrome.exe",
    },
    {
        "name": "Microsoft Edge",
        "registry_app_path": r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        "registry_version_paths": [
            (r"Software\Microsoft\Edge\BLBeacon", "version"),
        ],
        "user_data_env": "LOCALAPPDATA",
        "user_data_subpath": r"Microsoft\Edge\User Data",
        "exe_relative": r"Microsoft\Edge\Application\msedge.exe",
    },
]

# Browsers we explicitly do NOT scan (for transparency).
_UNSUPPORTED_BROWSERS = ["Mozilla Firefox", "Opera", "Brave", "Vivaldi", "Safari"]


# ============================================================
# SAFETY HELPERS
# ============================================================

def _is_sensitive_file(filename: str) -> bool:
    """Return True if the filename matches a known sensitive browser file."""
    return filename.strip().lower() in _SENSITIVE_FILENAMES


# ============================================================
# WINDOWS REGISTRY HELPERS
# ============================================================

def _read_registry_string(hkey_root, subkey: str, value_name: str = "") -> Optional[str]:
    """
    Read a single string value from the Windows registry (KEY_READ only).
    Returns None on any failure.
    """
    if sys.platform != "win32":
        return None
    try:
        import winreg
        with winreg.OpenKey(hkey_root, subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return str(val).strip() if val else None
    except OSError:
        return None


def _registry_key_exists(hkey_root, subkey: str) -> bool:
    """Check whether a registry key exists (KEY_READ only)."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(hkey_root, subkey, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


# ============================================================
# BROWSER DETECTION (WINDOWS)
# ============================================================

def _detect_windows_browser(browser_spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect a single browser on Windows.
    Returns a dict with detection results and source information.
    """
    if sys.platform != "win32":
        return {"detected": False, "sources_checked": [], "sources_failed": []}

    import winreg

    name = browser_spec["name"]
    detected = False
    version: Optional[str] = None
    detection_source: Optional[str] = None
    sources_checked: List[str] = []
    sources_failed: List[str] = []

    # --- 1. Registry App Path ---
    reg_app = browser_spec["registry_app_path"]
    source_label = f"Registry App Path ({reg_app})"
    sources_checked.append(source_label)
    try:
        if _registry_key_exists(winreg.HKEY_LOCAL_MACHINE, reg_app):
            detected = True
            detection_source = "Windows Registry (App Paths)"
        else:
            sources_failed.append(source_label)
    except Exception:
        sources_failed.append(source_label)

    # --- 2. Registry version ---
    for reg_ver_path, reg_ver_name in browser_spec["registry_version_paths"]:
        source_label = f"Registry Version ({reg_ver_path})"
        sources_checked.append(source_label)
        try:
            ver = _read_registry_string(winreg.HKEY_LOCAL_MACHINE, reg_ver_path, reg_ver_name)
            if ver:
                version = ver
                if not detected:
                    detected = True
                    detection_source = f"Windows Registry ({reg_ver_path})"
            else:
                # Also try HKCU
                ver = _read_registry_string(winreg.HKEY_CURRENT_USER, reg_ver_path, reg_ver_name)
                if ver:
                    version = ver
                    if not detected:
                        detected = True
                        detection_source = f"Windows Registry HKCU ({reg_ver_path})"
                else:
                    sources_failed.append(source_label)
        except Exception:
            sources_failed.append(source_label)

    # --- 3. Filesystem exe check ---
    env_var = browser_spec["user_data_env"]
    base_dir = os.environ.get(env_var, "")
    if base_dir:
        exe_path = os.path.join(base_dir, browser_spec["exe_relative"])
        source_label = f"Filesystem ({exe_path})"
        sources_checked.append(source_label)
        try:
            if os.path.isfile(exe_path):
                if not detected:
                    detected = True
                    detection_source = "Filesystem (executable)"
            else:
                sources_failed.append(source_label)
        except PermissionError:
            sources_failed.append(f"{source_label} [PermissionError]")
    else:
        sources_failed.append(f"Filesystem ({env_var} not set)")

    return {
        "detected": detected,
        "name": name,
        "version": version,
        "detection_source": detection_source,
        "sources_checked": sources_checked,
        "sources_failed": sources_failed,
    }


# ============================================================
# EXTENSION METADATA PARSING
# ============================================================

def _resolve_extension_i18n(ver_path: str, text: str, default_locale: Optional[str] = None) -> str:
    """Resolve __MSG_...__ placeholders using extension's _locales directory if available."""
    if not (text.startswith("__MSG_") and text.endswith("__") and len(text) > 8):
        return text
    key = text[6:-2]
    locales_dir = os.path.join(ver_path, "_locales")
    if not os.path.isdir(locales_dir):
        return text

    candidates = []
    if default_locale:
        candidates.append(default_locale)
    candidates.extend(["en", "en_US", "en_GB"])

    for loc in candidates:
        msg_file = os.path.join(locales_dir, loc, "messages.json")
        if os.path.isfile(msg_file):
            try:
                with open(msg_file, "r", encoding="utf-8", errors="replace") as f:
                    messages = json.load(f)
                if isinstance(messages, dict):
                    for k, val in messages.items():
                        if k.lower() == key.lower() and isinstance(val, dict):
                            resolved = val.get("message")
                            if resolved and isinstance(resolved, str):
                                return resolved.strip()
            except Exception:
                pass
    return text


def _parse_extension_manifest(manifest_path: str) -> Optional[Dict[str, Any]]:
    """
    Parse a Chromium extension manifest.json and extract safe metadata.
    Returns None if the file cannot be read or is malformed.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    name = data.get("name")
    if not name or not isinstance(name, str):
        return None

    ver_path = os.path.dirname(manifest_path)
    default_locale = data.get("default_locale")
    if default_locale and not isinstance(default_locale, str):
        default_locale = None

    ext_name = _resolve_extension_i18n(ver_path, name.strip(), default_locale)

    ext_version = data.get("version")
    if ext_version and isinstance(ext_version, str):
        ext_version = ext_version.strip()
    else:
        ext_version = None

    ext_description = data.get("description")
    if ext_description and isinstance(ext_description, str):
        resolved_desc = _resolve_extension_i18n(ver_path, ext_description.strip(), default_locale)
        ext_description = resolved_desc[:200]  # Truncate long descriptions
    else:
        ext_description = None

    return {
        "name": ext_name,
        "version": ext_version,
        "description": ext_description,
    }


def _collect_profile_extensions(
    profile_path: str,
    profile_label: str,
    browser_name: str,
) -> Dict[str, Any]:
    """
    Collect extension metadata from a single Chromium profile directory.
    Returns a dict with extensions list and any errors encountered.
    """
    extensions_dir = os.path.join(profile_path, "Extensions")
    result: Dict[str, Any] = {
        "profile_label": profile_label,
        "extensions": [],
        "errors": [],
    }

    if not os.path.isdir(extensions_dir):
        result["errors"].append(f"Extensions directory not found: {extensions_dir}")
        return result

    try:
        ext_ids = os.listdir(extensions_dir)
    except PermissionError:
        result["errors"].append(f"Permission denied reading: {extensions_dir}")
        return result
    except OSError as e:
        result["errors"].append(f"Cannot list extensions directory: {e}")
        return result

    seen_extensions = set()  # Deduplication within this profile

    for ext_id in ext_ids:
        ext_id_path = os.path.join(extensions_dir, ext_id)
        if not os.path.isdir(ext_id_path):
            continue

        # Each extension ID directory contains version subdirectories
        try:
            version_dirs = os.listdir(ext_id_path)
        except PermissionError:
            result["errors"].append(f"Permission denied: {ext_id_path}")
            continue
        except OSError:
            continue

        for ver_dir in version_dirs:
            ver_path = os.path.join(ext_id_path, ver_dir)
            if not os.path.isdir(ver_path):
                continue

            manifest_path = os.path.join(ver_path, "manifest.json")
            if not os.path.isfile(manifest_path):
                continue

            # Safety check: never read sensitive files
            if _is_sensitive_file("manifest.json"):
                continue  # pragma: no cover — manifest.json is not in the blocklist

            parsed = _parse_extension_manifest(manifest_path)
            if parsed is None:
                result["errors"].append(
                    f"Malformed manifest: {manifest_path}"
                )
                continue

            # Deduplication key: (ext_id, version)
            dedup_key = (ext_id.lower(), (parsed["version"] or "").lower())
            if dedup_key in seen_extensions:
                continue
            seen_extensions.add(dedup_key)

            result["extensions"].append({
                "extension_id": ext_id,
                "name": parsed["name"],
                "version": parsed["version"],
                "description": parsed["description"],
                "browser": browser_name,
                "profile": profile_label,
            })

    return result


# ============================================================
# PROFILE DISCOVERY
# ============================================================

def _discover_profiles(user_data_path: str) -> List[Dict[str, str]]:
    """
    Discover Chromium profile directories under a User Data path.
    Returns a list of {"label": ..., "path": ...} dicts.
    Only looks for known profile directory prefixes — no recursive crawl.
    """
    profiles: List[Dict[str, str]] = []

    if not os.path.isdir(user_data_path):
        return profiles

    try:
        entries = os.listdir(user_data_path)
    except (PermissionError, OSError):
        return profiles

    for entry in entries:
        # Only consider known profile directory patterns
        is_profile = False
        for prefix in _PROFILE_DIR_PREFIXES:
            if entry == prefix or entry.startswith(prefix):
                is_profile = True
                break

        if not is_profile:
            continue

        full_path = os.path.join(user_data_path, entry)
        if os.path.isdir(full_path):
            profiles.append({
                "label": entry,  # Privacy-preserving: folder name only
                "path": full_path,
            })

    return profiles


# ============================================================
# MAIN SCANNER (WINDOWS)
# ============================================================

def _scan_windows_browsers() -> Dict[str, Any]:
    """
    Scan for Chrome and Edge on Windows.
    Returns structured results with browsers, extensions, coverage, and errors.
    """
    browsers_found: List[Dict[str, Any]] = []
    all_extensions: List[Dict[str, Any]] = []
    coverage: Dict[str, Any] = {
        "browsers_searched": [],
        "browsers_detected": [],
        "browsers_not_detected": [],
        "unsupported_browsers": _UNSUPPORTED_BROWSERS[:],
        "profiles_scanned": 0,
        "extensions_found": 0,
        "sources_checked": [],
        "sources_failed": [],
    }
    errors: List[str] = []

    for browser_spec in _WINDOWS_BROWSERS:
        browser_name = browser_spec["name"]
        coverage["browsers_searched"].append(browser_name)

        # Detect browser
        detection = _detect_windows_browser(browser_spec)
        coverage["sources_checked"].extend(detection["sources_checked"])
        coverage["sources_failed"].extend(detection["sources_failed"])

        if not detection["detected"]:
            coverage["browsers_not_detected"].append(browser_name)
            continue

        coverage["browsers_detected"].append(browser_name)

        browser_info: Dict[str, Any] = {
            "name": browser_name,
            "version": detection.get("version"),
            "detection_source": detection.get("detection_source", "Unknown"),
            "profiles": [],
            "extension_count": 0,
        }

        # Discover profiles
        env_var = browser_spec["user_data_env"]
        base_dir = os.environ.get(env_var, "")
        if not base_dir:
            errors.append(f"{browser_name}: {env_var} environment variable not set")
            browsers_found.append(browser_info)
            continue

        user_data_path = os.path.join(base_dir, browser_spec["user_data_subpath"])

        if not os.path.isdir(user_data_path):
            errors.append(
                f"{browser_name}: User Data directory not found at {user_data_path}"
            )
            browsers_found.append(browser_info)
            continue

        profiles = _discover_profiles(user_data_path)

        if not profiles:
            errors.append(
                f"{browser_name}: No profile directories found under {user_data_path}"
            )
            browsers_found.append(browser_info)
            continue

        for profile in profiles:
            coverage["profiles_scanned"] += 1
            profile_result = _collect_profile_extensions(
                profile["path"], profile["label"], browser_name
            )
            browser_info["profiles"].append(profile["label"])
            browser_info["extension_count"] += len(profile_result["extensions"])
            all_extensions.extend(profile_result["extensions"])
            errors.extend(profile_result["errors"])

        browsers_found.append(browser_info)

    # Global deduplication of extensions across browsers/profiles
    seen_global = set()
    deduped_extensions: List[Dict[str, Any]] = []
    for ext in all_extensions:
        key = (
            ext["extension_id"].lower(),
            (ext["version"] or "").lower(),
            ext["browser"].lower(),
        )
        if key in seen_global:
            continue
        seen_global.add(key)
        deduped_extensions.append(ext)

    coverage["extensions_found"] = len(deduped_extensions)

    # Determine overall status
    if browsers_found:
        status = "SUCCESS"
    elif coverage["browsers_searched"]:
        status = "PARTIAL"
    else:
        status = "UNAVAILABLE"

    return {
        "status": status,
        "browsers": browsers_found,
        "extensions": deduped_extensions,
        "coverage": coverage,
        "unavailable_sources": coverage["sources_failed"],
        "errors": errors,
    }


# ============================================================
# PUBLIC API
# ============================================================

async def check_browsers() -> Dict[str, Any]:
    """
    Main entry point for browser footprint scanning.
    Platform-aware router: currently supports Windows only.

    Returns a dict with:
        status: "SUCCESS" | "PARTIAL" | "UNAVAILABLE"
        browsers: list of detected browser info dicts
        extensions: list of extension metadata dicts
        coverage: dict describing what was and was not scanned
        unavailable_sources: list of sources that could not be checked
        errors: list of non-fatal error messages
    """
    current_os = platform.system()

    if current_os == "Windows":
        return _scan_windows_browsers()

    # Non-Windows: report as unavailable
    return {
        "status": "UNAVAILABLE",
        "browsers": [],
        "extensions": [],
        "coverage": {
            "browsers_searched": [],
            "browsers_detected": [],
            "browsers_not_detected": [],
            "unsupported_browsers": _UNSUPPORTED_BROWSERS[:],
            "profiles_scanned": 0,
            "extensions_found": 0,
            "sources_checked": [],
            "sources_failed": [
                f"Browser footprint scanning is not yet supported on {current_os}"
            ],
        },
        "unavailable_sources": [
            f"Browser footprint scanning is not yet supported on {current_os}"
        ],
        "errors": [],
    }

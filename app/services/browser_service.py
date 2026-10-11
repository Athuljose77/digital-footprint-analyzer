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

import configparser
import json
import os
import platform
import re
import shutil
import subprocess
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

# Supported browsers and their Linux-specific metadata.
_LINUX_BROWSERS: List[Dict[str, Any]] = [
    {
        "name": "Mozilla Firefox",
        "type": "firefox",
        "binaries": ["firefox", "firefox-esr", "firefox-bin"],
        "fallback_paths": [
            "/usr/bin/firefox",
            "/usr/bin/firefox-esr",
            "/usr/lib64/firefox/firefox",
            "/usr/lib/firefox/firefox",
            "/opt/firefox/firefox",
            "/usr/local/bin/firefox",
            "/var/lib/flatpak/exports/bin/org.mozilla.firefox",
            os.path.expanduser("~/.local/share/flatpak/exports/bin/org.mozilla.firefox"),
            "/snap/bin/firefox",
        ],
        "profile_roots": [
            "~/.mozilla/firefox",
            "~/.var/app/org.mozilla.firefox/.mozilla/firefox",
            "~/snap/firefox/common/.mozilla/firefox",
        ],
    },
    {
        "name": "Google Chrome",
        "type": "chromium",
        "binaries": ["google-chrome", "google-chrome-stable", "google-chrome-beta", "google-chrome-unstable"],
        "fallback_paths": [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/opt/google/chrome/google-chrome",
            "/usr/local/bin/google-chrome",
            "/var/lib/flatpak/exports/bin/com.google.Chrome",
            os.path.expanduser("~/.local/share/flatpak/exports/bin/com.google.Chrome"),
        ],
        "user_data_paths": [
            "~/.config/google-chrome",
            "~/.var/app/com.google.Chrome/config/google-chrome",
        ],
    },
    {
        "name": "Chromium",
        "type": "chromium",
        "binaries": ["chromium", "chromium-browser"],
        "fallback_paths": [
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/lib64/chromium-browser/chromium-browser",
            "/usr/lib/chromium-browser/chromium-browser",
            "/snap/bin/chromium",
            "/usr/local/bin/chromium",
            "/var/lib/flatpak/exports/bin/org.chromium.Chromium",
            os.path.expanduser("~/.local/share/flatpak/exports/bin/org.chromium.Chromium"),
        ],
        "user_data_paths": [
            "~/.config/chromium",
            "~/.var/app/org.chromium.Chromium/config/chromium",
            "~/snap/chromium/common/chromium",
        ],
    },
    {
        "name": "Microsoft Edge",
        "type": "chromium",
        "binaries": ["microsoft-edge", "microsoft-edge-stable", "microsoft-edge-beta", "microsoft-edge-dev"],
        "fallback_paths": [
            "/usr/bin/microsoft-edge",
            "/usr/bin/microsoft-edge-stable",
            "/opt/microsoft/msedge/msedge",
            "/usr/local/bin/microsoft-edge",
            "/var/lib/flatpak/exports/bin/com.microsoft.Edge",
            os.path.expanduser("~/.local/share/flatpak/exports/bin/com.microsoft.Edge"),
        ],
        "user_data_paths": [
            "~/.config/microsoft-edge",
            "~/.var/app/com.microsoft.Edge/config/microsoft-edge",
        ],
    },
    {
        "name": "Brave",
        "type": "chromium",
        "binaries": ["brave-browser", "brave-browser-stable", "brave"],
        "fallback_paths": [
            "/usr/bin/brave-browser",
            "/usr/bin/brave-browser-stable",
            "/opt/brave.com/brave/brave-browser",
            "/usr/bin/brave",
            "/usr/local/bin/brave-browser",
            "/var/lib/flatpak/exports/bin/com.brave.Browser",
            os.path.expanduser("~/.local/share/flatpak/exports/bin/com.brave.Browser"),
            "/snap/bin/brave",
        ],
        "user_data_paths": [
            "~/.config/BraveSoftware/Brave-Browser",
            "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
            "~/snap/brave/common/BraveSoftware/Brave-Browser",
        ],
    },
    {
        "name": "Zen Browser",
        "type": "firefox",
        "binaries": ["zen", "zen-browser", "zen-bin", "zen-browser-bin"],
        "fallback_paths": [
            "~/.local/bin/zen",
            "~/.local/bin/zen-browser",
            "/usr/bin/zen",
            "/usr/bin/zen-browser",
            "/usr/bin/zen-bin",
            "/usr/local/bin/zen",
            "/usr/local/bin/zen-browser",
            "/opt/zen/zen",
            "/opt/zen/zen-bin",
            "/opt/zen-browser/zen",
            "/opt/zen-browser/zen-bin",
            "~/.tarball-installations/zen/zen",
            "~/.tarball-installations/zen/zen-bin",
            "/var/lib/flatpak/exports/bin/io.github.zen_browser.zen",
            "/var/lib/flatpak/exports/bin/app.zen_browser.zen",
            "~/.local/share/flatpak/exports/bin/io.github.zen_browser.zen",
            "~/.local/share/flatpak/exports/bin/app.zen_browser.zen",
            "/snap/bin/zen",
            "/snap/bin/zen-browser",
        ],
        "profile_roots": [
            "~/.config/zen",
            "~/.zen",
            "~/.var/app/io.github.zen_browser.zen/.config/zen",
            "~/.var/app/io.github.zen_browser.zen/.zen",
            "~/.var/app/app.zen_browser.zen/.config/zen",
            "~/.var/app/app.zen_browser.zen/.zen",
            "~/snap/zen/common/.config/zen",
            "~/snap/zen/common/.zen",
        ],
    },
]

_UNSUPPORTED_BROWSERS_LINUX = ["Opera", "Vivaldi", "Safari", "Tor Browser"]


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
    executable_path: Optional[str] = None
    if base_dir:
        exe_path = os.path.join(base_dir, browser_spec["exe_relative"])
        source_label = f"Filesystem ({exe_path})"
        sources_checked.append(source_label)
        try:
            if os.path.isfile(exe_path):
                if not detected:
                    detected = True
                    detection_source = "Filesystem (executable)"
                executable_path = exe_path
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
        "executable_path": executable_path,
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
            "executable_path": detection.get("executable_path"),
            "detection_source": detection.get("detection_source", "Unknown"),
            "profiles": [],
            "profile_paths": [],
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
            browser_info["profile_paths"].append(profile["path"])
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
# LINUX BROWSER DETECTION & PROFILE PARSING
# ============================================================

def _detect_linux_browser(browser_spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect a single browser on Linux.
    Checks PATH via shutil.which, standard executable paths, and profile locations.
    Extracts version via '<exe> --version' or local version files safely.
    Never executes browser profile data or opens sensitive files.
    """
    name = browser_spec["name"]
    binaries = browser_spec.get("binaries", [])
    fallback_paths = browser_spec.get("fallback_paths", [])

    detected = False
    executable_path: Optional[str] = None
    version: Optional[str] = None
    detection_source: Optional[str] = None
    sources_checked: List[str] = []
    sources_failed: List[str] = []

    # 1. Check PATH
    for bin_name in binaries:
        source_label = f"PATH ({bin_name})"
        sources_checked.append(source_label)
        found = shutil.which(bin_name)
        if found and os.path.isfile(found):
            detected = True
            executable_path = found
            detection_source = f"System PATH ({found})"
            break
        else:
            sources_failed.append(source_label)

    # 2. Check fallback standard filesystem paths
    if not detected:
        for path in fallback_paths:
            exp_path = os.path.expanduser(path)
            source_label = f"Filesystem ({exp_path})"
            sources_checked.append(source_label)
            try:
                if os.path.isfile(exp_path) and os.access(exp_path, os.X_OK):
                    detected = True
                    executable_path = exp_path
                    detection_source = f"Filesystem ({exp_path})"
                    break
                else:
                    sources_failed.append(source_label)
            except PermissionError:
                sources_failed.append(f"{source_label} [PermissionError]")
            except Exception:
                sources_failed.append(source_label)

    # 3. Check profile/user data roots if executable was not found
    if not detected:
        check_roots = browser_spec.get("user_data_paths", []) + browser_spec.get("profile_roots", [])
        for raw_root in check_roots:
            exp_root = os.path.expanduser(raw_root)
            source_label = f"Profile directory ({exp_root})"
            sources_checked.append(source_label)
            if os.path.isdir(exp_root):
                detected = True
                detection_source = f"Profile directory ({exp_root})"
                break
            else:
                sources_failed.append(source_label)

    # 4. Version detection
    if executable_path:
        try:
            proc = subprocess.run(
                [executable_path, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0 and proc.stdout:
                match = re.search(r"(\d+(?:\.\d+)+[a-zA-Z0-9\-_.]*)", proc.stdout)
                if match:
                    version = match.group(1).rstrip(".")
        except Exception:
            pass

    # Fallback version detection if CLI version check failed or produced nothing
    if version is None and browser_spec.get("type") == "chromium":
        for raw_path in browser_spec.get("user_data_paths", []):
            exp_path = os.path.expanduser(raw_path)
            lv_file = os.path.join(exp_path, "Last Version")
            if os.path.isfile(lv_file):
                try:
                    with open(lv_file, "r", encoding="utf-8", errors="replace") as f:
                        v_text = f.read().strip()
                    match = re.search(r"(\d+(?:\.\d+)+[a-zA-Z0-9\-_.]*)", v_text)
                    if match:
                        version = match.group(1).rstrip(".")
                        break
                except (OSError, PermissionError):
                    pass

    if version is None and browser_spec.get("type") == "firefox":
        for raw_root in browser_spec.get("profile_roots", []):
            exp_root = os.path.expanduser(raw_root)
            if os.path.isdir(exp_root):
                try:
                    for entry in os.listdir(exp_root):
                        sub_p = os.path.join(exp_root, entry)
                        if os.path.isdir(sub_p):
                            compat_file = os.path.join(sub_p, "compatibility.ini")
                            if os.path.isfile(compat_file):
                                try:
                                    with open(compat_file, "r", encoding="utf-8", errors="replace") as f:
                                        for line in f:
                                            if line.startswith("LastVersion="):
                                                v_str = line.split("=", 1)[1].strip()
                                                match = re.search(r"(\d+(?:\.\d+)+[a-zA-Z0-9\-_.]*)", v_str)
                                                if match:
                                                    version = match.group(1).rstrip(".")
                                                    break
                                except Exception:
                                    pass
                        if version:
                            break
                except Exception:
                    pass
            if version:
                break

    return {
        "detected": detected,
        "name": name,
        "version": version,
        "executable_path": executable_path,
        "detection_source": detection_source,
        "sources_checked": sources_checked,
        "sources_failed": sources_failed,
    }


def _discover_firefox_profiles(profile_root: str) -> List[Dict[str, str]]:
    """
    Discover Firefox profiles under a profile root (e.g. ~/.mozilla/firefox).
    Reads profiles.ini if present, or identifies directory names safely.
    Returns list of {"label": ..., "path": ...} dicts.
    """
    profiles: List[Dict[str, str]] = []
    if not os.path.isdir(profile_root):
        return profiles

    ini_path = os.path.join(profile_root, "profiles.ini")
    if os.path.isfile(ini_path):
        cp = configparser.ConfigParser()
        try:
            cp.read(ini_path, encoding="utf-8")
            for section in cp.sections():
                if section.lower().startswith("profile"):
                    label = cp.get(section, "Name", fallback=section).strip()
                    p_path = cp.get(section, "Path", fallback="").strip()
                    is_rel = cp.get(section, "IsRelative", fallback="1").strip()
                    if p_path:
                        full_path = os.path.join(profile_root, p_path) if is_rel == "1" else p_path
                        if os.path.isdir(full_path):
                            profiles.append({"label": label, "path": full_path})
        except Exception:
            pass

    if not profiles:
        try:
            entries = os.listdir(profile_root)
            for entry in entries:
                full_path = os.path.join(profile_root, entry)
                if not os.path.isdir(full_path):
                    continue
                if ".default" in entry or os.path.isfile(os.path.join(full_path, "prefs.js")):
                    profiles.append({"label": entry, "path": full_path})
        except (PermissionError, OSError):
            pass

    return profiles


def _collect_firefox_profile_extensions(
    profile_path: str,
    profile_label: str,
    browser_name: str,
) -> Dict[str, Any]:
    """
    Collect extension metadata from a Firefox profile directory.
    Reads extensions.json or extensions/ directory safely (read-only).
    Never accesses sensitive databases (history, cookies, logins).
    """
    result: Dict[str, Any] = {
        "profile_label": profile_label,
        "extensions": [],
        "errors": [],
    }

    if not os.path.isdir(profile_path):
        result["errors"].append(f"Profile directory not found: {profile_path}")
        return result

    seen_extensions = set()

    # Source 1: extensions.json
    ext_json_path = os.path.join(profile_path, "extensions.json")
    if os.path.isfile(ext_json_path):
        try:
            with open(ext_json_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, dict):
                addons = data.get("addons", [])
                if isinstance(addons, list):
                    for addon in addons:
                        if not isinstance(addon, dict):
                            continue
                        addon_type = addon.get("type")
                        if addon_type not in ("extension", None):
                            continue
                        ext_id = addon.get("id") or ""
                        default_loc = addon.get("defaultLocale")
                        if isinstance(default_loc, dict):
                            ext_name = default_loc.get("name") or addon.get("name")
                            ext_desc = default_loc.get("description") or addon.get("description")
                        else:
                            ext_name = addon.get("name")
                            ext_desc = addon.get("description")

                        if not ext_name or not isinstance(ext_name, str):
                            continue

                        ext_ver = addon.get("version")
                        if ext_ver and isinstance(ext_ver, str):
                            ext_ver = ext_ver.strip()
                        else:
                            ext_ver = None

                        if ext_desc and isinstance(ext_desc, str):
                            ext_desc = ext_desc.strip()[:200]
                        else:
                            ext_desc = None

                        dedup_key = (ext_id.lower(), (ext_ver or "").lower())
                        if dedup_key in seen_extensions:
                            continue
                        seen_extensions.add(dedup_key)

                        result["extensions"].append({
                            "extension_id": ext_id,
                            "name": ext_name.strip(),
                            "version": ext_ver,
                            "description": ext_desc,
                            "browser": browser_name,
                            "profile": profile_label,
                        })
        except PermissionError:
            result["errors"].append(f"Permission denied reading: {ext_json_path}")
        except Exception as e:
            result["errors"].append(f"Error reading {ext_json_path}: {e}")

    # Source 2: extensions directory if extensions.json had nothing
    if not result["extensions"]:
        ext_dir = os.path.join(profile_path, "extensions")
        if os.path.isdir(ext_dir):
            try:
                entries = os.listdir(ext_dir)
                for entry in entries:
                    if entry.endswith(".xpi"):
                        ext_id = entry[:-4]
                        dedup_key = (ext_id.lower(), "")
                        if dedup_key in seen_extensions:
                            continue
                        seen_extensions.add(dedup_key)
                        result["extensions"].append({
                            "extension_id": ext_id,
                            "name": ext_id,
                            "version": None,
                            "description": None,
                            "browser": browser_name,
                            "profile": profile_label,
                        })
                    else:
                        sub_dir = os.path.join(ext_dir, entry)
                        if os.path.isdir(sub_dir):
                            manifest_path = os.path.join(sub_dir, "manifest.json")
                            if os.path.isfile(manifest_path):
                                parsed = _parse_extension_manifest(manifest_path)
                                if parsed:
                                    dedup_key = (entry.lower(), (parsed["version"] or "").lower())
                                    if dedup_key in seen_extensions:
                                        continue
                                    seen_extensions.add(dedup_key)
                                    result["extensions"].append({
                                        "extension_id": entry,
                                        "name": parsed["name"],
                                        "version": parsed["version"],
                                        "description": parsed["description"],
                                        "browser": browser_name,
                                        "profile": profile_label,
                                    })
            except PermissionError:
                result["errors"].append(f"Permission denied reading: {ext_dir}")
            except OSError as e:
                result["errors"].append(f"Error reading extensions directory {ext_dir}: {e}")

    return result


def _scan_linux_browsers() -> Dict[str, Any]:
    """
    Scan for supported browsers on Linux (Firefox, Chrome, Chromium, Edge, Brave, Zen Browser).
    Returns structured results with browsers, extensions, coverage, and errors.
    """
    browsers_found: List[Dict[str, Any]] = []
    all_extensions: List[Dict[str, Any]] = []
    coverage: Dict[str, Any] = {
        "browsers_searched": [],
        "browsers_detected": [],
        "browsers_not_detected": [],
        "unsupported_browsers": _UNSUPPORTED_BROWSERS_LINUX[:],
        "profiles_scanned": 0,
        "extensions_found": 0,
        "sources_checked": [],
        "sources_failed": [],
    }
    errors: List[str] = []

    for browser_spec in _LINUX_BROWSERS:
        browser_name = browser_spec["name"]
        browser_type = browser_spec.get("type", "chromium")
        coverage["browsers_searched"].append(browser_name)

        detection = _detect_linux_browser(browser_spec)
        coverage["sources_checked"].extend(detection["sources_checked"])
        coverage["sources_failed"].extend(detection["sources_failed"])

        if not detection["detected"]:
            coverage["browsers_not_detected"].append(browser_name)
            continue

        coverage["browsers_detected"].append(browser_name)

        browser_info: Dict[str, Any] = {
            "name": browser_name,
            "version": detection.get("version"),
            "executable_path": detection.get("executable_path"),
            "detection_source": detection.get("detection_source", "Unknown"),
            "profiles": [],
            "profile_paths": [],
            "extension_count": 0,
        }

        # Profile and extension scanning
        if browser_type == "chromium":
            user_data_paths = browser_spec.get("user_data_paths", [])
            found_any_user_data = False
            for p in user_data_paths:
                exp = os.path.expanduser(p)
                if not os.path.isdir(exp):
                    continue
                found_any_user_data = True
                profiles = _discover_profiles(exp)
                for profile in profiles:
                    coverage["profiles_scanned"] += 1
                    profile_result = _collect_profile_extensions(
                        profile["path"], profile["label"], browser_name
                    )
                    browser_info["profiles"].append(profile["label"])
                    browser_info["profile_paths"].append(profile["path"])
                    browser_info["extension_count"] += len(profile_result["extensions"])
                    all_extensions.extend(profile_result["extensions"])
                    errors.extend(profile_result["errors"])

            if not found_any_user_data:
                errors.append(f"{browser_name}: User Data directory not found")
            elif not browser_info["profiles"]:
                errors.append(f"{browser_name}: No profile directories found")

            browsers_found.append(browser_info)

        elif browser_type == "firefox":
            profile_roots = browser_spec.get("profile_roots", [])
            found_any_root = False
            for r in profile_roots:
                exp = os.path.expanduser(r)
                if not os.path.isdir(exp):
                    continue
                found_any_root = True
                profiles = _discover_firefox_profiles(exp)
                for profile in profiles:
                    coverage["profiles_scanned"] += 1
                    profile_result = _collect_firefox_profile_extensions(
                        profile["path"], profile["label"], browser_name
                    )
                    browser_info["profiles"].append(profile["label"])
                    browser_info["profile_paths"].append(profile["path"])
                    browser_info["extension_count"] += len(profile_result["extensions"])
                    all_extensions.extend(profile_result["extensions"])
                    errors.extend(profile_result["errors"])

            if not found_any_root:
                errors.append(f"{browser_name}: Profile directory not found")
            elif not browser_info["profiles"]:
                errors.append(f"{browser_name}: No profile directories found")

            browsers_found.append(browser_info)

    # Global deduplication of extensions across browsers/profiles
    seen_global = set()
    deduped_extensions: List[Dict[str, Any]] = []
    for ext in all_extensions:
        key = (
            ext.get("extension_id", "").lower(),
            (ext.get("version") or "").lower(),
            ext.get("browser", "").lower(),
        )
        if key in seen_global:
            continue
        seen_global.add(key)
        deduped_extensions.append(ext)

    coverage["extensions_found"] = len(deduped_extensions)

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
    Platform-aware router: supports Windows and Linux.

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
    elif current_os == "Linux":
        return _scan_linux_browsers()

    # Other OS (macOS, BSD, etc.): report as unavailable
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

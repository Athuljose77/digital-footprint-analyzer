import os
import sys
import json
import time
import tempfile
import asyncio
import subprocess
from unittest import mock

# Ensure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.browser_service import (
    _parse_extension_manifest,
    _collect_profile_extensions,
    _discover_profiles,
    _discover_firefox_profiles,
    _collect_firefox_profile_extensions,
    _detect_linux_browser,
    _scan_linux_browsers,
    _is_sensitive_file,
    _scan_windows_browsers,
    _detect_windows_browser,
    _WINDOWS_BROWSERS,
    _LINUX_BROWSERS,
    _UNSUPPORTED_BROWSERS,
    _UNSUPPORTED_BROWSERS_LINUX,
    _SENSITIVE_FILENAMES,
    check_browsers,
)
from app.core.scan_controller import run_browser_scan, run_system_scan, run_file_metadata_scan
from app.models.common import ScanResult, FootprintData, Finding
from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow
from app.ui.workers import ScanWorker


# ============================================================
# 1. SENSITIVE FILE PROTECTION & SAFETY
# ============================================================

def test_sensitive_file_protection():
    print("--- 1. Testing Sensitive File Protection ---")
    sensitive_samples = [
        "history", "cookies", "login data", "web data",
        "passwords", "bookmarks", "sessions", "session storage",
        "favicons", "current session", "last session"
    ]
    for s in sensitive_samples:
        assert _is_sensitive_file(s), f"Expected '{s}' to be blocked as sensitive"
        assert _is_sensitive_file(s.upper()), f"Expected case-insensitive block for '{s}'"

    # Non-sensitive files must not be blocked
    assert not _is_sensitive_file("manifest.json")
    assert not _is_sensitive_file("extensions.json")
    assert not _is_sensitive_file("profiles.ini")
    print("Sensitive file protection verified.")


# ============================================================
# 2. PLATFORM-AWARE ROUTER (LINUX & WINDOWS & OTHER)
# ============================================================

def test_platform_aware_router():
    print("\n--- 2. Testing Platform-Aware Router ---")
    # 2.1 Live check on current platform
    res = asyncio.run(check_browsers())
    assert isinstance(res, dict)
    assert "status" in res
    assert "coverage" in res

    if sys.platform.startswith("linux"):
        assert res["status"] in ("SUCCESS", "PARTIAL"), f"Expected SUCCESS or PARTIAL on Linux, got {res['status']}"
        assert res["status"] != "UNAVAILABLE", "Linux must not return UNAVAILABLE!"
        coverage = res["coverage"]
        assert "Mozilla Firefox" in coverage["browsers_searched"]
        assert "Brave" in coverage["browsers_searched"]
        print(f"Linux live scan succeeded: status={res['status']}, detected={coverage['browsers_detected']}")

    # 2.2 Mocked unsupported platform (e.g. Darwin / macOS)
    with mock.patch("platform.system", return_value="Darwin"):
        darwin_res = asyncio.run(check_browsers())
        assert darwin_res["status"] == "UNAVAILABLE"
        assert darwin_res["browsers"] == []
        assert "Darwin" in darwin_res["unavailable_sources"][0]
        print("Unsupported platform (Darwin) correctly returned UNAVAILABLE.")


# ============================================================
# 3. CHROMIUM EXTENSION MANIFEST PARSING (READ-ONLY)
# ============================================================

def test_extension_manifest_parsing():
    print("\n--- 3. Testing Extension Manifest Parsing ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = os.path.join(tmpdir, "manifest.json")

        # 3.1 Valid manifest
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": "Privacy Protector",
                "version": "1.2.3",
                "description": "An open source privacy tool."
            }, f)
        res = _parse_extension_manifest(manifest_path)
        assert res is not None
        assert res["name"] == "Privacy Protector"
        assert res["version"] == "1.2.3"
        assert res["description"] == "An open source privacy tool."

        # 3.2 Rich manifest with sensitive fields (must ignore permissions/scripts)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": "Rich Ext",
                "version": "2.0.0",
                "permissions": ["cookies", "history", "tabs"],
                "content_scripts": [{"matches": ["*://*/*"]}],
                "description": "A rich extension"
            }, f)
        res = _parse_extension_manifest(manifest_path)
        assert res is not None
        assert res["name"] == "Rich Ext"
        assert "permissions" not in res
        assert "content_scripts" not in res

        # 3.3 Truncation of long descriptions (>200 chars)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "name": "Long Desc",
                "description": "X" * 300
            }, f)
        res = _parse_extension_manifest(manifest_path)
        assert res is not None
        assert len(res["description"]) == 200

        # 3.4 Malformed JSON
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("{not valid json!!}")
        assert _parse_extension_manifest(manifest_path) is None

        # 3.5 Missing file
        assert _parse_extension_manifest(os.path.join(tmpdir, "missing.json")) is None
    print("Chromium extension manifest parsing verified.")


# ============================================================
# 4. CHROMIUM PROFILE & EXTENSION COLLECTION
# ============================================================

def test_chromium_profile_and_extension_collection():
    print("\n--- 4. Testing Chromium Profile Extension Collection ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        profile_dir = os.path.join(tmpdir, "Default")
        ext_dir = os.path.join(profile_dir, "Extensions", "ext-id-123", "1.0_0")
        os.makedirs(ext_dir, exist_ok=True)

        manifest_path = os.path.join(ext_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({"name": "Test Extension", "version": "1.0"}, f)

        res = _collect_profile_extensions(profile_dir, "Default", "Google Chrome")
        assert len(res["extensions"]) == 1
        ext = res["extensions"][0]
        assert ext["extension_id"] == "ext-id-123"
        assert ext["name"] == "Test Extension"
        assert ext["browser"] == "Google Chrome"
        assert ext["profile"] == "Default"

        # Missing extensions directory handled gracefully
        empty_profile = os.path.join(tmpdir, "Profile 1")
        os.makedirs(empty_profile, exist_ok=True)
        res_empty = _collect_profile_extensions(empty_profile, "Profile 1", "Google Chrome")
        assert res_empty["extensions"] == []
        assert len(res_empty["errors"]) > 0
    print("Chromium profile extension collection verified.")


# ============================================================
# 5. FIREFOX PROFILE DISCOVERY & EXTENSION PARSING
# ============================================================

def test_firefox_profile_and_extensions():
    print("\n--- 5. Testing Firefox Profile & Extension Parsing ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        # 5.1 Test profiles.ini parsing
        profile_dir = os.path.join(tmpdir, "xxxx.default-release")
        os.makedirs(profile_dir, exist_ok=True)

        ini_path = os.path.join(tmpdir, "profiles.ini")
        with open(ini_path, "w", encoding="utf-8") as f:
            f.write("[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=xxxx.default-release\nDefault=1\n")

        profiles = _discover_firefox_profiles(tmpdir)
        assert len(profiles) == 1
        assert profiles[0]["label"] == "default-release"
        assert profiles[0]["path"] == profile_dir

        # 5.2 Test Firefox extensions.json parsing
        ext_json_path = os.path.join(profile_dir, "extensions.json")
        with open(ext_json_path, "w", encoding="utf-8") as f:
            json.dump({
                "schemaVersion": 35,
                "addons": [
                    {
                        "id": "uBlock0@raymondhill.net",
                        "defaultLocale": {
                            "name": "uBlock Origin",
                            "description": "An efficient blocker."
                        },
                        "version": "1.55.0",
                        "type": "extension",
                        "active": True
                    },
                    {
                        "id": "theme@mozilla.org",
                        "name": "Dark Theme",
                        "type": "theme",  # Non-extension should be ignored
                        "active": True
                    }
                ]
            }, f)

        res = _collect_firefox_profile_extensions(profile_dir, "default-release", "Mozilla Firefox")
        assert len(res["extensions"]) == 1
        ext = res["extensions"][0]
        assert ext["name"] == "uBlock Origin"
        assert ext["extension_id"] == "uBlock0@raymondhill.net"
        assert ext["version"] == "1.55.0"
        assert ext["browser"] == "Mozilla Firefox"

        # 5.3 Test missing extensions.json with extensions/ directory (.xpi)
        profile_dir2 = os.path.join(tmpdir, "yyyy.test-profile")
        os.makedirs(os.path.join(profile_dir2, "extensions"), exist_ok=True)
        open(os.path.join(profile_dir2, "extensions", "sample-addon@example.com.xpi"), "w").close()

        res2 = _collect_firefox_profile_extensions(profile_dir2, "test-profile", "Mozilla Firefox")
        assert len(res2["extensions"]) == 1
        assert res2["extensions"][0]["extension_id"] == "sample-addon@example.com"

        # 5.4 Missing profile directory handled gracefully
        res_missing = _collect_firefox_profile_extensions(os.path.join(tmpdir, "nonexistent"), "none", "Mozilla Firefox")
        assert res_missing["extensions"] == []
        assert len(res_missing["errors"]) > 0

    print("Firefox profile and extension collection verified.")


# ============================================================
# 6. LINUX BROWSER DETECTION (MOCKED SCENARIOS)
# ============================================================

def test_linux_browser_detection_mocked():
    print("\n--- 6. Testing Linux Browser Detection Mock Scenarios ---")
    spec = {
        "name": "Test Browser",
        "type": "chromium",
        "binaries": ["test-browser"],
        "fallback_paths": ["/opt/test-browser/test-browser"],
        "user_data_paths": ["~/.config/test-browser"],
    }

    # 6.1 Detected via PATH with working --version
    with mock.patch("shutil.which", return_value="/usr/bin/test-browser"), \
         mock.patch("os.path.isfile", return_value=True), \
         mock.patch("subprocess.run") as mock_subproc:

        mock_subproc.return_value = mock.Mock(returncode=0, stdout="Test Browser 124.0.5000.10\n")
        det = _detect_linux_browser(spec)
        assert det["detected"] is True
        assert det["executable_path"] == "/usr/bin/test-browser"
        assert det["version"] == "124.0.5000.10"
        assert "System PATH" in det["detection_source"]

    # 6.2 Version failure handled gracefully (subprocess timeout or error)
    with mock.patch("shutil.which", return_value="/usr/bin/test-browser"), \
         mock.patch("os.path.isfile", return_value=True), \
         mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test-browser", timeout=3)):

        det = _detect_linux_browser(spec)
        assert det["detected"] is True
        assert det["executable_path"] == "/usr/bin/test-browser"
        assert det["version"] is None  # Gracefully handled without crash

    # 6.3 Missing browser scenario (not on PATH, not in fallback, no user data)
    with mock.patch("shutil.which", return_value=None), \
         mock.patch("os.path.isfile", return_value=False), \
         mock.patch("os.path.isdir", return_value=False):

        det = _detect_linux_browser(spec)
        assert det["detected"] is False
        assert det["executable_path"] is None
        assert len(det["sources_failed"]) > 0

    print("Linux browser detection mock scenarios passed.")


# ============================================================
# 7. ZEN BROWSER MOCK SCENARIOS & FIREFOX SEPARATION
# ============================================================

def test_zen_browser_mock_scenarios():
    print("\n--- 7. Testing Zen Browser Mock Scenarios & Firefox Separation ---")
    zen_spec = next((b for b in _LINUX_BROWSERS if b["name"] == "Zen Browser"), None)
    assert zen_spec is not None, "Zen Browser must be defined in _LINUX_BROWSERS"
    assert zen_spec["name"] == "Zen Browser", "Zen Browser name must be 'Zen Browser'"
    assert zen_spec["type"] == "firefox"

    # 7.1 Zen executable detected through PATH
    with mock.patch("shutil.which", return_value="/usr/local/bin/zen"), \
         mock.patch("os.path.isfile", return_value=True), \
         mock.patch("subprocess.run") as mock_subproc:

        mock_subproc.return_value = mock.Mock(returncode=0, stdout="Mozilla Zen 1.22.2b\n")
        det = _detect_linux_browser(zen_spec)
        assert det["detected"] is True
        assert det["name"] == "Zen Browser"
        assert det["name"] != "Mozilla Firefox"
        assert det["executable_path"] == "/usr/local/bin/zen"
        assert det["version"] == "1.22.2b"
        assert "System PATH" in det["detection_source"]

    # 7.2 Zen executable detected through fallback path (e.g. ~/.local/bin/zen)
    fallback_zen = os.path.expanduser("~/.local/bin/zen")
    with mock.patch("shutil.which", return_value=None), \
         mock.patch("os.path.isfile", side_effect=lambda p: p == fallback_zen), \
         mock.patch("os.access", return_value=True), \
         mock.patch("subprocess.run") as mock_subproc:

        mock_subproc.return_value = mock.Mock(returncode=0, stdout="Mozilla Zen 1.22.2b\n")
        det = _detect_linux_browser(zen_spec)
        assert det["detected"] is True
        assert det["name"] == "Zen Browser"
        assert det["executable_path"] == fallback_zen

    # 7.3 Zen version failure / timeout handled gracefully
    with mock.patch("shutil.which", return_value="/usr/local/bin/zen"), \
         mock.patch("os.path.isfile", return_value=True), \
         mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="zen", timeout=3)):

        det = _detect_linux_browser(zen_spec)
        assert det["detected"] is True
        assert det["version"] is None or isinstance(det["version"], str)

    # 7.4 Missing Zen executable
    with mock.patch("shutil.which", return_value=None), \
         mock.patch("os.path.isfile", return_value=False), \
         mock.patch("os.path.isdir", return_value=False):

        det = _detect_linux_browser(zen_spec)
        assert det["detected"] is False

    # 7.5 Zen profile & extension discovery in mock directory
    with tempfile.TemporaryDirectory() as tmpdir:
        zen_root = os.path.join(tmpdir, ".config", "zen")
        profile_dir = os.path.join(zen_root, "xxxx.Default (release)")
        os.makedirs(profile_dir, exist_ok=True)

        ini_path = os.path.join(zen_root, "profiles.ini")
        with open(ini_path, "w", encoding="utf-8") as f:
            f.write("[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=Default (release)\nIsRelative=1\nPath=xxxx.Default (release)\nDefault=1\n")

        profiles = _discover_firefox_profiles(zen_root)
        assert len(profiles) == 1
        assert profiles[0]["label"] == "Default (release)"

        # Write extension in Zen profile
        ext_json_path = os.path.join(profile_dir, "extensions.json")
        with open(ext_json_path, "w", encoding="utf-8") as f:
            json.dump({
                "schemaVersion": 35,
                "addons": [
                    {
                        "id": "uBlock0@raymondhill.net",
                        "defaultLocale": {"name": "uBlock Origin", "description": "Ad blocker."},
                        "version": "1.75.0",
                        "type": "extension",
                        "active": True
                    }
                ]
            }, f)

        res = _collect_firefox_profile_extensions(profile_dir, "Default (release)", "Zen Browser")
        assert len(res["extensions"]) == 1
        ext = res["extensions"][0]
        assert ext["browser"] == "Zen Browser"
        assert ext["browser"] != "Mozilla Firefox"
        assert ext["name"] == "uBlock Origin"
        assert ext["version"] == "1.75.0"

    print("Zen Browser mock scenarios and Firefox separation passed.")


# ============================================================
# 8. LINUX SCANNER WITH ALL BROWSERS MISSING (GRACEFUL HANDLING)
# ============================================================

def test_linux_scanner_all_missing_mocked():
    print("\n--- 8. Testing Linux Scanner When No Browsers Found ---")
    with mock.patch("app.services.browser_service._detect_linux_browser") as mock_detect:
        mock_detect.return_value = {
            "detected": False,
            "name": "Mock",
            "version": None,
            "executable_path": None,
            "detection_source": None,
            "sources_checked": ["PATH (mock)"],
            "sources_failed": ["PATH (mock)"],
        }
        res = _scan_linux_browsers()
        assert res["status"] == "PARTIAL"
        assert res["browsers"] == []
        assert res["extensions"] == []
        assert len(res["coverage"]["browsers_not_detected"]) == len(_LINUX_BROWSERS)

        # Scan controller test with no browsers
        with mock.patch("app.services.browser_service.check_browsers", return_value=res):
            ctrl_res = asyncio.run(run_browser_scan())
            assert ctrl_res.status == "COMPLETED"
            assert "No supported browsers detected" in ctrl_res.message
    print("All-missing browsers scenario handled gracefully.")


# ============================================================
# 8. WINDOWS SCANNER MOCKS (REGRESSION CHECK)
# ============================================================

def test_windows_scanner_mocked():
    print("\n--- 8. Testing Windows Scanner Mock Logic ---")
    with mock.patch("app.services.browser_service.sys") as mock_sys, \
         mock.patch("app.services.browser_service._detect_windows_browser") as mock_detect, \
         mock.patch("app.services.browser_service._discover_profiles") as mock_disc, \
         mock.patch("os.path.isdir", return_value=True), \
         mock.patch.dict(os.environ, {"LOCALAPPDATA": "/fake"}):

        mock_sys.platform = "win32"
        mock_detect.side_effect = lambda spec: {
            "detected": True if "Chrome" in spec["name"] else False,
            "version": "120.0.6099.130" if "Chrome" in spec["name"] else None,
            "executable_path": r"C:\Program Files\Google\Chrome\chrome.exe" if "Chrome" in spec["name"] else None,
            "detection_source": "Registry App Path" if "Chrome" in spec["name"] else None,
            "sources_checked": ["Registry App Path"],
            "sources_failed": [] if "Chrome" in spec["name"] else ["Registry App Path"],
        }
        mock_disc.return_value = [{"path": "/fake/Default", "label": "Default"}]

        scan_res = _scan_windows_browsers()
        assert scan_res["status"] == "SUCCESS"
        assert len(scan_res["browsers"]) == 1
        b = scan_res["browsers"][0]
        assert b["name"] == "Google Chrome"
        assert b["version"] == "120.0.6099.130"
        assert "Default" in b["profiles"]
        print("Windows scanner mock verification passed.")


# ============================================================
# 9. SCAN CONTROLLER INTEGRATION
# ============================================================

def test_scan_controller_browser_scan():
    print("\n--- 10. Testing Scan Controller run_browser_scan() ---")
    res = asyncio.run(run_browser_scan())
    assert isinstance(res, ScanResult)
    assert res.scan_type == "Browser"
    assert res.analysis_mode == "My Footprint"
    assert res.scan_category == "Browser Footprint"
    assert res.status == "COMPLETED"
    assert len(res.footprint_data) > 0
    # On this Fedora machine, Firefox, Brave, and Zen Browser should be detected
    browser_data = [fd for fd in res.footprint_data if fd.subcategory == "Detected Browser"]
    assert len(browser_data) >= 1, "Expected at least 1 detected browser in footprint data on Fedora"
    for bd in browser_data:
        assert "Path:" in bd.value, f"Expected executable path in footprint data: {bd.value}"

    detected_values = [bd.value for bd in browser_data]
    # Verify Zen Browser is detected distinctly from Firefox
    zen_entries = [v for v in detected_values if v.startswith("Zen Browser")]
    assert len(zen_entries) == 1, f"Expected Zen Browser entry in footprint data, got: {detected_values}"
    assert "Zen Browser" in zen_entries[0]
    assert "Mozilla Firefox" not in zen_entries[0]
    print(f"ScanController returned valid ScanResult: status={res.status}, message='{res.message}'")


# ============================================================
# 11. UI & WORKER INTEGRATION & CONCURRENCY GUARD
# ============================================================

def test_ui_and_worker_integration():
    print("\n--- 11. Testing UI Tabs, Worker Dispatch, and Concurrency ---")
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    window = MainWindow()

    def wait_for_worker():
        if window.worker:
            while not window.worker.isFinished():
                app.processEvents()
                time.sleep(0.02)
            window.worker.wait()
            app.processEvents()

    # 11.1 Verify Tabs
    assert hasattr(window, "my_footprint_tabs")
    tab_titles = [window.my_footprint_tabs.tabText(i) for i in range(window.my_footprint_tabs.count())]
    assert "System Footprint" in tab_titles
    assert "Browser Footprint" in tab_titles
    assert "File & Metadata Footprint" in tab_titles
    print(f"Verified My Footprint tabs: {tab_titles}")

    # 11.2 Verify Browser Widgets
    assert hasattr(window, "browser_scan_btn")
    assert hasattr(window, "browser_status_label")
    assert hasattr(window, "browser_results_area")
    assert window.browser_results_area.isReadOnly()

    # 11.3 Verify Worker Dispatch
    worker = ScanWorker("Browser", "")
    assert worker.scan_type == "Browser"

    # 11.4 Verify Concurrency Guard
    window.sidebar.setCurrentRow(1)
    window.my_footprint_tabs.setCurrentIndex(1)
    window.browser_scan_btn.click()
    worker1 = window.worker
    assert worker1 is not None and worker1.isRunning()

    # Attempt second click while worker is running
    window.browser_scan_btn.click()
    worker2 = window.worker
    assert worker1 is worker2, "Concurrency guard failed: second worker was spawned!"
    print("Browser concurrency guard verified.")

    wait_for_worker()
    assert window.browser_scan_btn.isEnabled()
    # Results area should display detected browsers
    text = window.browser_results_area.toPlainText()
    assert "FOOTPRINT DATA" in text
    assert ("Zen Browser" in text or "Firefox" in text or "Brave" in text or "No supported browsers" in text)
    print("UI Scan completion and result presentation verified.")

    app.quit()
    print("UI & worker integration passed.")


# ============================================================
# 12. REGRESSION TESTS (EXISTING MODULES)
# ============================================================

def test_regressions():
    print("\n--- 12. Testing System Footprint & File Metadata Regressions ---")
    # System scan regression
    sys_res = asyncio.run(run_system_scan())
    assert sys_res.scan_type == "System"
    assert sys_res.status == "COMPLETED"
    print("System scan regression passed.")

    # File metadata scan regression on clean temp file
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"sample file\n")
        tmp_name = f.name
    try:
        file_res = asyncio.run(run_file_metadata_scan(tmp_name))
        assert file_res.scan_type == "File & Metadata"
        assert file_res.status == "COMPLETED"
        print("File metadata regression passed.")
    finally:
        os.remove(tmp_name)


def main():
    test_sensitive_file_protection()
    test_platform_aware_router()
    test_extension_manifest_parsing()
    test_chromium_profile_and_extension_collection()
    test_firefox_profile_and_extensions()
    test_linux_browser_detection_mocked()
    test_zen_browser_mock_scenarios()
    test_linux_scanner_all_missing_mocked()
    test_windows_scanner_mocked()
    test_scan_controller_browser_scan()
    test_ui_and_worker_integration()
    test_regressions()
    print("\n============================================================")
    print("ALL BROWSER FOOTPRINT V1 TESTS COMPLETED SUCCESSFULLY!")
    print("============================================================")


if __name__ == "__main__":
    main()

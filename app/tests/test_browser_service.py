"""
Browser Footprint v1 — Test Suite

Comprehensive pytest-based tests covering:
  - Browser detection (Chrome, Edge, both, neither)
  - Missing browsers and missing profile directories
  - Extension metadata parsing (valid, minimal, rich, malformed)
  - Permission errors on registry and directories
  - Deduplication (within profile and across profiles)
  - Unsupported browsers and incomplete coverage reporting
  - Controller and shared-model integration
  - UI integration (button exists, scan triggers, results render)
  - Regressions for existing Email, Username, and System scans

Uses temporary directories and mocked filesystem/registry data.
Does not depend on having a particular browser installed.
"""

import asyncio
import json
import os
import sys
import uuid
from unittest import mock

import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app.services.browser_service import (
    _parse_extension_manifest,
    _collect_profile_extensions,
    _discover_profiles,
    _is_sensitive_file,
    _scan_windows_browsers,
    _UNSUPPORTED_BROWSERS,
    check_browsers,
)
from app.models.common import ScanResult, FootprintData, Finding


# ============================================================
# HELPERS
# ============================================================

def _create_extension(tmp_path, ext_id, version, manifest_data):
    """Create a realistic Chromium extension directory structure."""
    ext_dir = tmp_path / "Extensions" / ext_id / version
    ext_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = ext_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
    return str(manifest_path)


def _create_profile(tmp_path, profile_name="Default"):
    """Create a profile directory under tmp_path."""
    profile_dir = tmp_path / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)
    return str(profile_dir)


# ============================================================
# 1. EXTENSION MANIFEST PARSING
# ============================================================

class TestParseExtensionManifest:
    """Tests for _parse_extension_manifest."""

    def test_valid_manifest(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({
            "name": "uBlock Origin",
            "version": "1.52.0",
            "description": "An efficient blocker."
        }))
        result = _parse_extension_manifest(str(manifest))
        assert result is not None
        assert result["name"] == "uBlock Origin"
        assert result["version"] == "1.52.0"
        assert result["description"] == "An efficient blocker."

    def test_minimal_manifest(self, tmp_path):
        """Manifest with only a name — still valid."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"name": "Minimal Extension"}))
        result = _parse_extension_manifest(str(manifest))
        assert result is not None
        assert result["name"] == "Minimal Extension"
        assert result["version"] is None
        assert result["description"] is None

    def test_rich_manifest(self, tmp_path):
        """Manifest with extra fields — only safe fields extracted."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({
            "name": "Rich Extension",
            "version": "2.0.1",
            "description": "A rich test extension with many fields.",
            "permissions": ["tabs", "storage"],  # Should not appear in output
            "content_scripts": [{"matches": ["*://*/*"]}],
            "author": "Test Author",
        }))
        result = _parse_extension_manifest(str(manifest))
        assert result is not None
        assert result["name"] == "Rich Extension"
        assert result["version"] == "2.0.1"
        assert "permissions" not in result
        assert "content_scripts" not in result

    def test_malformed_json(self, tmp_path):
        """Invalid JSON returns None."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text("{not valid json!!!}")
        result = _parse_extension_manifest(str(manifest))
        assert result is None

    def test_empty_file(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text("")
        result = _parse_extension_manifest(str(manifest))
        assert result is None

    def test_missing_name(self, tmp_path):
        """Manifest without a name is invalid."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"version": "1.0"}))
        result = _parse_extension_manifest(str(manifest))
        assert result is None

    def test_name_not_string(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"name": 12345}))
        result = _parse_extension_manifest(str(manifest))
        assert result is None

    def test_nonexistent_file(self):
        result = _parse_extension_manifest("/nonexistent/path/manifest.json")
        assert result is None

    def test_long_description_truncated(self, tmp_path):
        """Descriptions longer than 200 chars are truncated."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({
            "name": "Truncation Test",
            "description": "A" * 300,
        }))
        result = _parse_extension_manifest(str(manifest))
        assert result is not None
        assert len(result["description"]) == 200

    def test_manifest_is_array(self, tmp_path):
        """manifest.json that is a JSON array, not object."""
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps([{"name": "Nope"}]))
        result = _parse_extension_manifest(str(manifest))
        assert result is None


# ============================================================
# 2. PROFILE EXTENSION COLLECTION
# ============================================================

class TestCollectProfileExtensions:
    """Tests for _collect_profile_extensions."""

    def test_no_extensions_dir(self, tmp_path):
        profile = _create_profile(tmp_path)
        result = _collect_profile_extensions(profile, "Default", "Chrome")
        assert result["extensions"] == []
        assert len(result["errors"]) > 0

    def test_valid_extensions(self, tmp_path):
        profile_path = _create_profile(tmp_path)
        _create_extension(
            tmp_path / "Default", "ext-abc", "1.0",
            {"name": "Test Ext", "version": "1.0", "description": "A test."}
        )
        result = _collect_profile_extensions(profile_path, "Default", "Chrome")
        assert len(result["extensions"]) == 1
        assert result["extensions"][0]["name"] == "Test Ext"
        assert result["extensions"][0]["extension_id"] == "ext-abc"
        assert result["extensions"][0]["browser"] == "Chrome"
        assert result["extensions"][0]["profile"] == "Default"

    def test_multiple_extensions(self, tmp_path):
        profile_path = _create_profile(tmp_path)
        _create_extension(
            tmp_path / "Default", "ext-1", "1.0",
            {"name": "Extension One", "version": "1.0"}
        )
        _create_extension(
            tmp_path / "Default", "ext-2", "2.5",
            {"name": "Extension Two", "version": "2.5"}
        )
        result = _collect_profile_extensions(profile_path, "Default", "Chrome")
        assert len(result["extensions"]) == 2
        names = {e["name"] for e in result["extensions"]}
        assert names == {"Extension One", "Extension Two"}

    def test_malformed_manifest_in_extension(self, tmp_path):
        profile_path = _create_profile(tmp_path)
        ext_dir = tmp_path / "Default" / "Extensions" / "bad-ext" / "1.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "manifest.json").write_text("{bad json}")
        result = _collect_profile_extensions(profile_path, "Default", "Chrome")
        assert len(result["extensions"]) == 0
        assert any("Malformed" in e for e in result["errors"])

    def test_permission_error_on_extensions_dir(self, tmp_path):
        profile_path = _create_profile(tmp_path)
        ext_dir = tmp_path / "Default" / "Extensions"
        ext_dir.mkdir(parents=True)
        with mock.patch("os.listdir", side_effect=PermissionError("Access denied")):
            result = _collect_profile_extensions(profile_path, "Default", "Chrome")
        assert len(result["extensions"]) == 0
        assert any("Permission denied" in e for e in result["errors"])

    def test_deduplication_within_profile(self, tmp_path):
        """Same ext_id + version should not be counted twice."""
        profile_path = _create_profile(tmp_path)
        # Create two version dirs with identical ext_id and version
        for ver_dir in ["1.0_0", "1.0_1"]:
            _create_extension(
                tmp_path / "Default", "dup-ext", ver_dir,
                {"name": "Duplicate Ext", "version": "1.0"}
            )
        result = _collect_profile_extensions(profile_path, "Default", "Chrome")
        # Should be deduplicated to 1
        assert len(result["extensions"]) == 1


# ============================================================
# 3. PROFILE DISCOVERY
# ============================================================

class TestDiscoverProfiles:
    """Tests for _discover_profiles."""

    def test_default_profile(self, tmp_path):
        (tmp_path / "Default").mkdir()
        profiles = _discover_profiles(str(tmp_path))
        assert len(profiles) == 1
        assert profiles[0]["label"] == "Default"

    def test_multiple_profiles(self, tmp_path):
        (tmp_path / "Default").mkdir()
        (tmp_path / "Profile 1").mkdir()
        (tmp_path / "Profile 2").mkdir()
        profiles = _discover_profiles(str(tmp_path))
        assert len(profiles) == 3
        labels = {p["label"] for p in profiles}
        assert labels == {"Default", "Profile 1", "Profile 2"}

    def test_nonexistent_path(self):
        profiles = _discover_profiles("/nonexistent/path")
        assert profiles == []

    def test_no_profile_dirs(self, tmp_path):
        """Directory exists but has no profile subdirectories."""
        (tmp_path / "SomeOtherDir").mkdir()
        (tmp_path / "Local State").touch()
        profiles = _discover_profiles(str(tmp_path))
        assert profiles == []

    def test_ignores_non_profile_dirs(self, tmp_path):
        """Only dirs matching profile prefixes are returned."""
        (tmp_path / "Default").mkdir()
        (tmp_path / "GrShaderCache").mkdir()
        (tmp_path / "Crashpad").mkdir()
        (tmp_path / "Profile 1").mkdir()
        profiles = _discover_profiles(str(tmp_path))
        labels = {p["label"] for p in profiles}
        assert labels == {"Default", "Profile 1"}

    def test_permission_denied(self, tmp_path):
        with mock.patch("os.listdir", side_effect=PermissionError):
            profiles = _discover_profiles(str(tmp_path))
        assert profiles == []


# ============================================================
# 4. SENSITIVE FILE GUARD
# ============================================================

class TestSensitiveFileGuard:
    """Tests for _is_sensitive_file."""

    def test_history_blocked(self):
        assert _is_sensitive_file("History") is True

    def test_cookies_blocked(self):
        assert _is_sensitive_file("Cookies") is True

    def test_login_data_blocked(self):
        assert _is_sensitive_file("Login Data") is True

    def test_manifest_allowed(self):
        assert _is_sensitive_file("manifest.json") is False

    def test_case_insensitive(self):
        assert _is_sensitive_file("HISTORY") is True
        assert _is_sensitive_file("cookies") is True


# ============================================================
# 5. BROWSER DETECTION (MOCKED WINDOWS)
# ============================================================

class TestBrowserDetection:
    """Tests for _detect_windows_browser with mocked winreg."""

    def _mock_detect(self, registry_exists=True, version="120.0.0.0",
                     exe_exists=True, browser_name="Google Chrome"):
        """Helper to run detection with mocked Windows environment."""
        from app.services.browser_service import _detect_windows_browser

        browser_spec = {
            "name": browser_name,
            "registry_app_path": r"Software\Test\AppPaths",
            "registry_version_paths": [
                (r"Software\Test\BLBeacon", "version"),
            ],
            "user_data_env": "LOCALAPPDATA",
            "user_data_subpath": r"Test\User Data",
            "exe_relative": r"Test\Application\test.exe",
        }

        mock_winreg = mock.MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 1
        mock_winreg.HKEY_CURRENT_USER = 2

        def mock_registry_key_exists(hkey, subkey):
            if subkey == browser_spec["registry_app_path"]:
                return registry_exists
            return False

        def mock_read_registry_string(hkey, subkey, value_name=""):
            if subkey == r"Software\Test\BLBeacon" and value_name == "version":
                return version
            return None

        with mock.patch.dict(os.environ, {"LOCALAPPDATA": "/fake/local"}), \
             mock.patch.dict("sys.modules", {"winreg": mock_winreg}), \
             mock.patch("app.services.browser_service.sys") as mock_sys, \
             mock.patch("app.services.browser_service._registry_key_exists", side_effect=mock_registry_key_exists), \
             mock.patch("app.services.browser_service._read_registry_string", side_effect=mock_read_registry_string), \
             mock.patch("os.path.isfile", return_value=exe_exists):
            mock_sys.platform = "win32"
            result = _detect_windows_browser(browser_spec)

        return result

    def test_chrome_detected_all_sources(self):
        result = self._mock_detect(registry_exists=True, version="120.0.0.0", exe_exists=True)
        assert result["detected"] is True
        assert result["version"] == "120.0.0.0"
        assert result["name"] == "Google Chrome"

    def test_chrome_not_detected(self):
        result = self._mock_detect(registry_exists=False, version=None, exe_exists=False)
        assert result["detected"] is False

    def test_chrome_registry_only(self):
        result = self._mock_detect(registry_exists=True, version="119.0.0.0", exe_exists=False)
        assert result["detected"] is True
        assert result["version"] == "119.0.0.0"

    def test_chrome_exe_only(self):
        result = self._mock_detect(registry_exists=False, version=None, exe_exists=True)
        assert result["detected"] is True

    def test_edge_detected(self):
        result = self._mock_detect(
            registry_exists=True, version="121.0.0.0",
            exe_exists=True, browser_name="Microsoft Edge"
        )
        assert result["detected"] is True
        assert result["name"] == "Microsoft Edge"


# ============================================================
# 6. FULL SCANNER (MOCKED)
# ============================================================

class TestScanWindowsBrowsers:
    """Tests for _scan_windows_browsers with mocked environment."""

    def test_no_browsers_detected(self):
        """When neither Chrome nor Edge is detected."""
        with mock.patch("app.services.browser_service.sys") as mock_sys, \
             mock.patch("app.services.browser_service._detect_windows_browser") as mock_detect:
            mock_sys.platform = "win32"
            mock_detect.return_value = {
                "detected": False,
                "name": "Test Browser",
                "version": None,
                "detection_source": None,
                "sources_checked": ["reg"],
                "sources_failed": ["reg"],
            }
            result = _scan_windows_browsers()

        assert result["status"] == "PARTIAL"
        assert len(result["browsers"]) == 0
        assert len(result["coverage"]["browsers_not_detected"]) == 2

    def test_browser_detected_no_profiles(self, tmp_path):
        """Browser detected but no profile directories found."""
        with mock.patch("app.services.browser_service.sys") as mock_sys, \
             mock.patch("app.services.browser_service._detect_windows_browser") as mock_detect, \
             mock.patch.dict(os.environ, {"LOCALAPPDATA": str(tmp_path)}):
            mock_sys.platform = "win32"
            mock_detect.return_value = {
                "detected": True,
                "name": "Google Chrome",
                "version": "120.0",
                "detection_source": "Windows Registry",
                "sources_checked": ["reg"],
                "sources_failed": [],
            }
            # Create user data path without any profile dirs
            user_data = tmp_path / "Google" / "Chrome" / "User Data"
            user_data.mkdir(parents=True)

            result = _scan_windows_browsers()

        assert result["status"] == "SUCCESS"
        assert len(result["browsers"]) >= 1
        # Should have errors about no profiles
        chrome_found = [b for b in result["browsers"] if b["name"] == "Google Chrome"]
        assert len(chrome_found) == 1

    def test_coverage_reports_unsupported_browsers(self):
        """Coverage always includes unsupported browser list."""
        with mock.patch("app.services.browser_service.sys") as mock_sys, \
             mock.patch("app.services.browser_service._detect_windows_browser") as mock_detect:
            mock_sys.platform = "win32"
            mock_detect.return_value = {
                "detected": False, "name": "Test",
                "version": None, "detection_source": None,
                "sources_checked": [], "sources_failed": [],
            }
            result = _scan_windows_browsers()

        assert "unsupported_browsers" in result["coverage"]
        assert "Mozilla Firefox" in result["coverage"]["unsupported_browsers"]
        assert "Opera" in result["coverage"]["unsupported_browsers"]


# ============================================================
# 7. DEDUPLICATION ACROSS PROFILES
# ============================================================

class TestGlobalDeduplication:
    """Tests for cross-profile extension deduplication."""

    def test_same_extension_different_profiles(self, tmp_path):
        """Same extension in Default and Profile 1 should be deduplicated by (id, version, browser)."""
        user_data = tmp_path / "User Data"
        for profile_name in ["Default", "Profile 1"]:
            _create_extension(
                user_data / profile_name, "shared-ext", "1.0",
                {"name": "Shared Ext", "version": "1.0"}
            )

        # Collect from both profiles
        results = []
        for pname in ["Default", "Profile 1"]:
            r = _collect_profile_extensions(
                str(user_data / pname), pname, "Chrome"
            )
            results.extend(r["extensions"])

        # Simulate global dedup logic from _scan_windows_browsers
        seen = set()
        deduped = []
        for ext in results:
            key = (ext["extension_id"].lower(), (ext["version"] or "").lower(), ext["browser"].lower())
            if key not in seen:
                seen.add(key)
                deduped.append(ext)

        assert len(deduped) == 1

    def test_different_versions_not_deduped(self, tmp_path):
        """Same extension ID with different versions should NOT be deduplicated."""
        user_data = tmp_path / "User Data"
        _create_extension(
            user_data / "Default", "evolving-ext", "1.0",
            {"name": "Evolving Ext", "version": "1.0"}
        )
        _create_extension(
            user_data / "Profile 1", "evolving-ext", "2.0",
            {"name": "Evolving Ext", "version": "2.0"}
        )

        results = []
        for pname in ["Default", "Profile 1"]:
            r = _collect_profile_extensions(
                str(user_data / pname), pname, "Chrome"
            )
            results.extend(r["extensions"])

        seen = set()
        deduped = []
        for ext in results:
            key = (ext["extension_id"].lower(), (ext["version"] or "").lower(), ext["browser"].lower())
            if key not in seen:
                seen.add(key)
                deduped.append(ext)

        # Different versions → both kept
        assert len(deduped) == 2


# ============================================================
# 8. NON-WINDOWS PLATFORM
# ============================================================

class TestNonWindowsPlatform:
    """Test behavior on non-Windows platforms."""

    def test_check_browsers_non_windows(self):
        with mock.patch("app.services.browser_service.platform") as mock_platform:
            mock_platform.system.return_value = "Darwin"
            result = asyncio.run(check_browsers())

        assert result["status"] == "UNAVAILABLE"
        assert len(result["browsers"]) == 0
        assert "Darwin" in result["unavailable_sources"][0]

    def test_coverage_on_non_windows(self):
        with mock.patch("app.services.browser_service.platform") as mock_platform:
            mock_platform.system.return_value = "Darwin"
            result = asyncio.run(check_browsers())

        assert result["coverage"]["unsupported_browsers"] == _UNSUPPORTED_BROWSERS


# ============================================================
# 9. CONTROLLER INTEGRATION
# ============================================================

class TestControllerIntegration:
    """Test that run_browser_scan produces valid ScanResult."""

    def test_run_browser_scan_returns_scan_result(self):
        from app.core.scan_controller import run_browser_scan

        mock_data = {
            "status": "SUCCESS",
            "browsers": [
                {"name": "Google Chrome", "version": "120.0", "detection_source": "Registry",
                 "profiles": ["Default"], "extension_count": 2}
            ],
            "extensions": [
                {"extension_id": "abc", "name": "Ext A", "version": "1.0",
                 "description": "Test", "browser": "Chrome", "profile": "Default"},
                {"extension_id": "def", "name": "Ext B", "version": "2.0",
                 "description": None, "browser": "Chrome", "profile": "Default"},
            ],
            "coverage": {
                "browsers_searched": ["Google Chrome", "Microsoft Edge"],
                "browsers_detected": ["Google Chrome"],
                "browsers_not_detected": ["Microsoft Edge"],
                "unsupported_browsers": ["Mozilla Firefox"],
                "profiles_scanned": 1,
                "extensions_found": 2,
                "sources_checked": ["reg"],
                "sources_failed": [],
            },
            "unavailable_sources": [],
            "errors": [],
        }

        with mock.patch("app.core.scan_controller.check_browsers",
                         return_value=mock_data):
            result = asyncio.run(run_browser_scan())

        assert isinstance(result, ScanResult)
        assert result.scan_type == "Browser"
        assert result.scan_category == "Browser Footprint"
        assert result.status == "COMPLETED"
        assert len(result.footprint_data) > 0
        assert len(result.findings) > 0

        # Check FootprintData categories
        categories = {fd.category for fd in result.footprint_data}
        assert "Browser" in categories

        # Check we have browser + extension data
        subcategories = {fd.subcategory for fd in result.footprint_data}
        assert "Detected Browser" in subcategories
        assert "Extension" in subcategories

    def test_run_browser_scan_unavailable_platform(self):
        from app.core.scan_controller import run_browser_scan

        mock_data = {
            "status": "UNAVAILABLE",
            "browsers": [],
            "extensions": [],
            "coverage": {},
            "unavailable_sources": ["Not supported on Linux"],
            "errors": [],
        }

        with mock.patch("app.core.scan_controller.check_browsers",
                         return_value=mock_data):
            result = asyncio.run(run_browser_scan())

        assert result.status == "COMPLETED"
        assert "not available" in result.message.lower()

    def test_run_browser_scan_exception_handling(self):
        from app.core.scan_controller import run_browser_scan

        with mock.patch("app.core.scan_controller.check_browsers",
                         side_effect=RuntimeError("Unexpected failure")):
            result = asyncio.run(run_browser_scan())

        assert result.status == "ERROR"
        assert "Unexpected failure" in result.message


# ============================================================
# 10. SHARED MODEL INTEGRATION
# ============================================================

class TestSharedModelIntegration:
    """Verify that Browser Footprint data fits the shared models."""

    def test_footprint_data_valid(self):
        fd = FootprintData(
            category="Browser",
            subcategory="Extension",
            source="Chrome Extension Directory",
            data_type="extension",
            value="uBlock Origin (v1.52.0) | ID: abc123",
            sensitivity="Low"
        )
        assert fd.category == "Browser"
        assert fd.data_type == "extension"

    def test_finding_valid(self):
        f = Finding(
            finding_id=str(uuid.uuid4()),
            finding_type="Scan Coverage",
            title="Browser Footprint Scan Coverage",
            description="Searched Chrome, Edge. Found Chrome.",
            evidence={"searched": ["Chrome", "Edge"], "detected": ["Chrome"]},
            severity="Info",
            status="Informational"
        )
        assert f.severity == "Info"
        assert isinstance(f.evidence, dict)

    def test_scan_result_with_browser_data(self):
        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            analysis_mode="My Footprint",
            scan_type="Browser",
            scan_category="Browser Footprint",
            status="COMPLETED",
            message="Test scan"
        )
        result.footprint_data.append(FootprintData(
            category="Browser", subcategory="Detected Browser",
            source="Registry", data_type="browser",
            value="Google Chrome — version 120.0", sensitivity="Low"
        ))
        assert len(result.footprint_data) == 1
        assert result.scan_type == "Browser"


# ============================================================
# 11. UI INTEGRATION
# ============================================================

class TestUIIntegration:
    """Test that the MainWindow has browser footprint UI elements."""

    @pytest.fixture
    def app_and_window(self):
        """Create a QApplication and MainWindow for testing."""
        from PySide6.QtWidgets import QApplication
        from app.ui.main_window import MainWindow

        # Reuse existing QApplication if one exists
        app = QApplication.instance()
        if app is None:
            app = QApplication([])
        window = MainWindow()
        yield app, window
        if hasattr(window, 'worker') and window.worker:
            try:
                if not window.worker.isFinished():
                    window.worker.wait(2000)
            except Exception:
                pass
        window.close()
        window.deleteLater()
        app.processEvents()

    def test_browser_button_exists(self, app_and_window):
        _, window = app_and_window
        assert hasattr(window, 'browser_scan_btn')
        assert window.browser_scan_btn.text() == "Browser Footprint"

    def test_browser_results_area_exists(self, app_and_window):
        _, window = app_and_window
        assert hasattr(window, 'browser_results_area')
        assert window.browser_results_area.isReadOnly()

    def test_browser_status_label_exists(self, app_and_window):
        _, window = app_and_window
        assert hasattr(window, 'browser_status_label')

    def test_browser_scan_triggers_worker(self, app_and_window):
        """Clicking the button should create a ScanWorker with type 'Browser'."""
        _, window = app_and_window
        window.sidebar.setCurrentRow(1)  # My Footprint page

        # Mock worker to avoid actual scan
        with mock.patch("app.ui.main_window.ScanWorker") as MockWorker:
            mock_instance = mock.MagicMock()
            mock_instance.isRunning.return_value = False
            MockWorker.return_value = mock_instance

            # Ensure no existing worker blocks us
            window.worker = None
            window.browser_scan_btn.click()

            MockWorker.assert_called_once_with("Browser", "")
            mock_instance.start.assert_called_once()

    def test_system_button_still_exists(self, app_and_window):
        """System Footprint button must not be removed."""
        _, window = app_and_window
        assert hasattr(window, 'sys_scan_btn')
        assert window.sys_scan_btn.text() == "System Footprint"

    def test_concurrency_guard_browser(self, app_and_window):
        """Second scan attempt while worker is running should be blocked."""
        _, window = app_and_window
        mock_worker = mock.MagicMock()
        mock_worker.isRunning.return_value = True
        window.worker = mock_worker

        window.start_browser_scan()
        # Should not have created a new worker — the existing one is still running
        assert window.worker is mock_worker

    def test_on_scan_complete_browser(self, app_and_window):
        """Test that browser scan results are rendered in the correct area."""
        _, window = app_and_window
        result = ScanResult(
            scan_id="test", analysis_mode="My Footprint",
            scan_type="Browser", scan_category="Browser Footprint",
            status="COMPLETED", message="Test complete"
        )
        result.footprint_data.append(FootprintData(
            category="Browser", subcategory="Detected Browser",
            source="Registry", data_type="browser",
            value="Google Chrome — version 120.0", sensitivity="Low"
        ))

        window.on_scan_complete(result)

        assert "Google Chrome" in window.browser_results_area.toPlainText()
        assert window.browser_scan_btn.isEnabled()

    def test_end_to_end_scan_workflow(self, app_and_window):
        """End-to-end integration test: click button, wait for worker, verify UI updates."""
        app, window = app_and_window
        window.sidebar.setCurrentRow(1)
        window.start_browser_scan()
        assert window.worker is not None
        while window.worker and not window.worker.isFinished():
            app.processEvents()
        if window.worker:
            window.worker.wait()
        app.processEvents()
        assert window.browser_scan_btn.isEnabled()
        assert "Status: COMPLETED" in window.browser_status_label.text()
        assert "=== FOOTPRINT DATA ===" in window.browser_results_area.toPlainText()


# ============================================================
# 12. REGRESSION TESTS
# ============================================================

class TestRegressions:
    """Verify existing scan types are not broken by Browser Footprint changes."""

    def test_email_scan_import(self):
        """Email scan function is still importable."""
        from app.core.scan_controller import run_email_scan
        assert callable(run_email_scan)

    def test_username_scan_import(self):
        """Username scan function is still importable."""
        from app.core.scan_controller import run_username_scan
        assert callable(run_username_scan)

    def test_system_scan_import(self):
        """System scan function is still importable."""
        from app.core.scan_controller import run_system_scan
        assert callable(run_system_scan)

    def test_worker_dispatches_all_types(self):
        """Worker should handle Email, Username, System, Browser."""
        from app.ui.workers import ScanWorker
        for scan_type in ["Email", "Username", "System", "Browser"]:
            worker = ScanWorker(scan_type, "test")
            assert worker.scan_type == scan_type

    def test_common_models_unchanged(self):
        """Shared models have their expected fields."""
        from app.models.common import ScanResult, FootprintData, Finding, Risk, Recommendation
        # Check ScanResult fields
        sr = ScanResult(
            scan_id="x", analysis_mode="test", scan_type="Email",
            scan_category="test", status="RUNNING"
        )
        assert hasattr(sr, 'footprint_data')
        assert hasattr(sr, 'findings')
        assert hasattr(sr, 'risks')
        assert hasattr(sr, 'recommendations')

    def test_system_scan_produces_result(self):
        """System scan still returns a valid ScanResult."""
        from app.core.scan_controller import run_system_scan
        result = asyncio.run(run_system_scan())
        assert isinstance(result, ScanResult)
        assert result.scan_type == "System"
        assert result.status in ("COMPLETED", "ERROR")

    @pytest.fixture
    def app_and_window(self):
        from PySide6.QtWidgets import QApplication
        from app.ui.main_window import MainWindow
        app = QApplication.instance()
        if app is None:
            app = QApplication([])
        window = MainWindow()
        yield app, window
        if hasattr(window, 'worker') and window.worker:
            try:
                if not window.worker.isFinished():
                    window.worker.wait(2000)
            except Exception:
                pass
        window.close()
        window.deleteLater()
        app.processEvents()

    def test_sidebar_has_all_pages(self, app_and_window):
        """Sidebar should still have Home, My Footprint, Public Lookup, Settings."""
        _, window = app_and_window
        items = [window.sidebar.item(i).text() for i in range(window.sidebar.count())]
        assert "Home" in items
        assert "My Footprint" in items
        assert "Public Lookup" in items
        assert "Settings" in items

    def test_email_username_combo_exists(self, app_and_window):
        """Email/Username combo on Public Lookup page is intact."""
        _, window = app_and_window
        assert hasattr(window, 'scan_type_combo')
        items = [window.scan_type_combo.itemText(i)
                 for i in range(window.scan_type_combo.count())]
        assert "Email" in items
        assert "Username" in items

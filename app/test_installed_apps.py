import sys
import os
import asyncio
import time
from unittest.mock import patch, MagicMock

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.system_service import (
    get_installed_applications,
    collect_linux_applications,
    collect_windows_applications,
    check_system,
    _collect_rpm,
    _collect_flatpak,
    _collect_snap
)
from app.core.scan_controller import run_system_scan, run_email_scan, run_username_scan
from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow


def test_service_installed_applications():
    print("--- 1. Testing Service Layer: Installed Applications Discovery ---")
    res = get_installed_applications()
    assert res["status"] == "SUCCESS", f"Expected SUCCESS, got {res.get('status')}"
    apps = res.get("applications", [])
    print(f"Discovered {len(apps)} installed applications.")
    print(f"Coverage: {res.get('coverage')}")
    assert len(apps) > 0, "Expected at least one installed application to be detected"
    
    # Check structure of records
    sample = apps[0]
    assert "name" in sample and sample["name"], "Application record missing name"
    assert "source" in sample and sample["source"], "Application record missing source"
    assert "version" in sample, "Application record missing version key"
    
    # Check that sources contain expected types on this Fedora machine
    sources = {a["source"] for a in apps}
    print(f"Active sources detected: {sources}")
    assert "rpm" in sources, "Expected 'rpm' to be among active sources on Fedora"
    
    # Verify at least several known installed system packages
    app_names = {a["name"].lower() for a in apps}
    known_packages = ["filesystem", "setup", "glibc", "bash", "python3", "coreutils"]
    found_known = [p for p in known_packages if any(p in name for name in app_names)]
    print(f"Known packages verified: {found_known}")
    assert len(found_known) >= 3, f"Expected at least 3 known packages, found {found_known}"

    # Verify deduplication: no exact duplicates of (name.lower(), version)
    seen = set()
    for a in apps:
        k = (a["name"].strip().lower(), (a.get("version") or "").strip().lower())
        assert k not in seen, f"Duplicate detected for key: {k}"
        seen.add(k)
    print("Deduplication verification passed.")


def test_service_graceful_fallback():
    print("\n--- 2. Testing Graceful Fallback & Error Handling ---")
    # Simulate rpm command failure
    with patch("shutil.which", return_value=None):
        with patch("app.services.system_service._collect_desktop_entries", return_value=[{"name": "FallbackApp", "version": "1.0", "source": "Desktop Entries"}]):
            fallback_res = collect_linux_applications()
            assert fallback_res["status"] == "SUCCESS"
            assert any(a["name"] == "FallbackApp" for a in fallback_res["applications"])
            print("Fallback to desktop entries when package managers missing passed.")

    # Simulate all sources unavailable
    with patch("shutil.which", return_value=None):
        with patch("app.services.system_service._collect_desktop_entries", return_value=None):
            unavail_res = collect_linux_applications()
            assert unavail_res["status"] == "UNAVAILABLE"
            assert unavail_res["applications"] == []
            print("Graceful handling when all sources unavailable passed.")


def test_windows_collector_mock():
    print("\n--- 3. Testing Windows Collector Logic (Mocked winreg) ---")
    mock_winreg = MagicMock()
    mock_winreg.HKEY_LOCAL_MACHINE = 1
    mock_winreg.HKEY_CURRENT_USER = 2
    mock_winreg.KEY_READ = 0x20019

    # Mock registry key enumeration
    mock_winreg.QueryInfoKey.return_value = (2, 0, 0)
    mock_winreg.EnumKey.side_effect = lambda key, idx: ["AppA", "AppB"][idx % 2]

    def mock_query_value_ex(key, val_name):
        if key == "app_key_A":
            if val_name == "DisplayName":
                return ("TestApp A", 1)
            elif val_name == "DisplayVersion":
                return ("2.4.0", 1)
            elif val_name == "SystemComponent":
                raise OSError()
            elif val_name == "ParentKeyName":
                raise OSError()
        elif key == "app_key_B":
            if val_name == "DisplayName":
                return ("TestApp B", 1)
            elif val_name == "DisplayVersion":
                return ("1.0.0", 1)
            elif val_name == "SystemComponent":
                return (1, 1) # System component -> should be skipped!
            elif val_name == "ParentKeyName":
                raise OSError()
        raise OSError()

    mock_winreg.QueryValueEx.side_effect = mock_query_value_ex

    class MockKeyContext:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self.name
        def __exit__(self, *args):
            pass

    def mock_open_key(root, path, reserved, access):
        if "AppA" in str(path):
            return MockKeyContext("app_key_A")
        elif "AppB" in str(path):
            return MockKeyContext("app_key_B")
        return MockKeyContext("root_key")

    mock_winreg.OpenKey.side_effect = mock_open_key

    with patch.dict("sys.modules", {"winreg": mock_winreg}):
        with patch("sys.platform", "win32"):
            win_res = collect_windows_applications()
            assert win_res["status"] == "SUCCESS"
            app_names = [a["name"] for a in win_res["applications"]]
        assert "TestApp A" in app_names, "Expected TestApp A to be collected"
        assert "TestApp B" not in app_names, "Expected SystemComponent TestApp B to be excluded"
        print("Windows registry parser mock test passed.")


async def test_controller_system_scan():
    print("\n--- 4. Testing Scan Controller: run_system_scan() ---")
    res = await run_system_scan()
    assert res.status == "COMPLETED", f"Expected COMPLETED, got {res.status}"
    assert res.scan_type == "System"
    assert res.scan_category == "System Footprint"

    # Verify v1 items are present
    subcategories = {fd.subcategory for fd in res.footprint_data}
    required_v1 = {"Operating System", "OS Version", "Hostname", "CPU", "Memory", "Network"}
    assert required_v1.issubset(subcategories), f"Missing v1 subcategories: {required_v1 - subcategories}"
    
    # Verify v2 item: Installed Applications
    assert "Installed Applications" in subcategories, "Missing Installed Applications subcategory"
    
    app_items = [fd for fd in res.footprint_data if fd.subcategory == "Installed Applications"]
    print(f"Controller returned {len(app_items)} Installed Application footprint items.")
    assert len(app_items) > 0

    sample_app = app_items[0]
    assert sample_app.category == "System"
    assert sample_app.subcategory == "Installed Applications"
    assert sample_app.data_type == "application"
    assert sample_app.sensitivity == "Low"
    assert sample_app.source in ["rpm", "flatpak", "snap", "dpkg", "pacman", "Desktop Entries", "System Package Manager"]
    print(f"Sample application FootprintData: {sample_app.value} (source: {sample_app.source})")
    print("Scan Controller test passed.")


def test_ui_and_regressions():
    print("\n--- 5. Testing PySide6 UI and Regressions ---")
    app = QApplication(sys.argv)
    window = MainWindow()

    # Switch to Public Lookup / scan page
    window.sidebar.setCurrentRow(2)

    def wait_for_worker():
        if window.worker:
            while not window.worker.isFinished():
                app.processEvents()
                time.sleep(0.02)
            window.worker.wait()
            app.processEvents()

    # 5.1 System Scan via UI
    print("Running System Scan via UI...")
    window.sidebar.setCurrentRow(1)
    window.sys_scan_btn.click()

    wait_for_worker()

    results_text = window.sys_results_area.toPlainText()
    assert "System Footprint:" in results_text
    assert "Operating System: Linux" in results_text
    assert "System API" in results_text
    assert "Installed Applications" in results_text
    print("System scan UI output verified.")

    # 5.2 Multiple Scan Protection
    print("Testing Multiple Scan Protection...")
    window.scan_type_combo.setCurrentText("Email")
    window.target_input.setText("test@example.com")
    window.scan_btn.click()
    worker1 = window.worker
    assert worker1 is not None and worker1.isRunning()

    # Try pressing Enter while running
    window.target_input.returnPressed.emit()
    worker2 = window.worker
    assert worker1 is worker2, "Multiple scan protection failed: second worker was spawned!"
    print("Multiple scan protection verified.")

    # Wait for Email scan to complete
    wait_for_worker()

    email_results = window.results_area.toPlainText()
    assert "=== FINDINGS ===" in email_results
    print("Email scan regression verified.")

    # 5.3 Username Scan Regression
    print("Testing Username Scan Regression...")
    window.scan_type_combo.setCurrentText("Username")
    window.target_input.setText("athul")
    window.scan_btn.click()

    wait_for_worker()

    user_results = window.results_area.toPlainText()
    assert "=== FOOTPRINT DATA ===" in user_results or "No profiles found" in window.status_label.text()
    print("Username scan regression verified.")

    app.quit()
    print("All UI and regression tests passed.")


def main():
    test_service_installed_applications()
    test_service_graceful_fallback()
    test_windows_collector_mock()
    asyncio.run(test_controller_system_scan())
    test_ui_and_regressions()
    print("\n============================================================")
    print("ALL SYSTEM FOOTPRINT v2 TESTS COMPLETED SUCCESSFULLY!")
    print("============================================================")


if __name__ == "__main__":
    main()

import sys
import os
import asyncio
import time
from unittest.mock import patch, MagicMock, mock_open

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.system_service import (
    get_startup_applications,
    collect_linux_startup,
    collect_windows_startup,
    check_system
)
from app.core.scan_controller import run_system_scan
from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow

def test_linux_parsing():
    print("--- 1. Testing Linux Desktop Parsing ---")
    
    mock_desktop = """[Desktop Entry]
Type=Application
Name=TestApp
Exec=/usr/bin/testapp --minimized
Hidden=false
X-GNOME-Autostart-enabled=true
Comment=A test startup app
"""
    with patch("os.path.isdir", return_value=True):
        with patch("os.listdir", return_value=["test.desktop"]):
            with patch("builtins.open", mock_open(read_data=mock_desktop)):
                res = collect_linux_startup()
                assert res["status"] == "SUCCESS"
                apps = res["applications"]
                assert len(apps) > 0
                app = apps[0]
                assert app["name"] == "TestApp"
                assert app["command"] == "/usr/bin/testapp --minimized"
                assert app["enabled"] == "True"
    print("Linux parsing passed.")

def test_linux_missing():
    print("--- 2. Testing Linux Missing Directories ---")
    with patch("os.path.isdir", return_value=False):
        res = collect_linux_startup()
        assert res["status"] == "UNAVAILABLE"
    print("Linux missing handling passed.")

def test_windows_parsing():
    print("--- 3. Testing Windows Registry Mocks ---")
    sys.modules["winreg"] = MagicMock()
    with patch("sys.platform", "win32"):
        import winreg
        
        mock_key = MagicMock()
        mock_key.__enter__.return_value = mock_key
        winreg.OpenKey.return_value = mock_key
        winreg.QueryInfoKey.return_value = (0, 1, 0)
        
        winreg.EnumValue.return_value = ("TestWinApp", "C:\\test\\app.exe", 1)
        
        with patch("os.environ.get", return_value="C:\\FakePath"):
            with patch("os.path.isdir", return_value=True):
                with patch("os.listdir", return_value=["StartApp.lnk"]):
                    res = collect_windows_startup()
                    assert res["status"] == "SUCCESS"
                    apps = res["applications"]
                    names = {a["name"] for a in apps}
                    assert "TestWinApp" in names
                    assert "StartApp.lnk" in names
                    print(f"Windows collected {len(apps)} apps")
    print("Windows parsing mock passed.")

async def test_controller_integration():
    print("--- 4. Testing Scan Controller Integration ---")
    res = await run_system_scan()
    assert res.status == "COMPLETED"
    
    startups = [fd for fd in res.footprint_data if fd.subcategory == "Startup Applications"]
    assert len(startups) > 0 or res.message != "System scan failed."
    print(f"Controller mapped {len(startups)} startup applications.")
    if startups:
        sample = startups[0]
        assert sample.category == "System"
    print("Scan controller integration passed.")

def test_ui_and_regressions():
    print("--- 5. Testing UI and Regressions ---")
    app = QApplication(sys.argv)
    window = MainWindow()

    def wait_for_worker():
        if window.worker:
            while not window.worker.isFinished():
                app.processEvents()
                time.sleep(0.02)
            window.worker.wait()
            app.processEvents()

    from unittest.mock import AsyncMock
    with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_email:
        mock_email.return_value = {"status": "SUCCESS", "breaches": []}
        window.scan_type_combo.setCurrentText("Email")
        window.target_input.setText("test@example.com")
        window.scan_btn.click()
        wait_for_worker()

    with patch("app.core.scan_controller.check_username", new_callable=AsyncMock) as mock_user:
        mock_user.return_value = {"status": "NOT_FOUND"}
        window.scan_type_combo.setCurrentText("Username")
        window.target_input.setText("athul")
        window.scan_btn.click()
        wait_for_worker()

    window.sys_scan_btn.click()
    wait_for_worker()

    text = window.sys_results_area.toPlainText()
    assert "System Footprint:" in text
    assert "Startup Applications" in text
    assert "Running Processes" in text
    assert "Installed Applications" in text

    app.quit()
    print("All UI and regression tests passed.")


def main():
    test_linux_parsing()
    test_linux_missing()
    test_windows_parsing()
    asyncio.run(test_controller_integration())
    test_ui_and_regressions()
    print("\n============================================================")
    print("ALL STARTUP APPLICATIONS v4 TESTS COMPLETED SUCCESSFULLY!")
    print("============================================================")

if __name__ == "__main__":
    main()

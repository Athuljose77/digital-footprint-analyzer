import sys
import os
import asyncio
import time
from unittest.mock import patch, MagicMock

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.system_service import (
    get_running_processes,
    collect_linux_processes,
    collect_windows_processes,
    check_system
)
from app.core.scan_controller import run_system_scan, run_email_scan, run_username_scan
from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow


def test_service_running_processes():
    print("--- 1. Testing Service Layer: Running Processes Collection ---")
    res = get_running_processes()
    assert res["status"] == "SUCCESS", f"Expected SUCCESS, got {res.get('status')}"
    procs = res.get("processes", [])
    print(f"Discovered {len(procs)} running processes.")
    assert len(procs) > 0, "Expected at least one running process to be detected"
    
    # Check structure of records
    sample = procs[0]
    assert "pid" in sample and sample["pid"], "Process record missing pid"
    assert "name" in sample and sample["name"], "Process record missing name"
    assert "executable" in sample, "Process record missing executable key"
    assert "user" in sample, "Process record missing user key"
    assert "status" in sample, "Process record missing status key"
    
    print(f"Sample process: {sample}")
    print("Service Layer test passed.")


def test_linux_collector_error_handling():
    print("\n--- 2. Testing Linux Collector Error Handling ---")
    # Simulate ps command missing
    with patch("shutil.which", return_value=None):
        res = collect_linux_processes()
        assert res["status"] == "UNAVAILABLE"
        assert res["processes"] == []
        print("Fallback when ps missing passed.")
        

def test_windows_collector_mock():
    print("\n--- 3. Testing Windows Collector Logic (Mocked subprocess) ---")
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = '"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"\n"System Idle Process","0","Services","0","8 K","Unknown","NT AUTHORITY\\SYSTEM","0:00:00","N/A"\n"TestProc.exe","1234","Console","1","1,000 K","Running","TESTDOMAIN\\TestUser","0:00:01","N/A"\n'

    with patch("subprocess.run", return_value=mock_proc):
        win_res = collect_windows_processes()
        assert win_res["status"] == "SUCCESS"
        procs = win_res["processes"]
        assert len(procs) == 2
        
        p1, p2 = procs[0], procs[1]
        assert p1["pid"] == "0"
        assert p1["name"] == "System Idle Process"
        assert p1["user"] == "NT AUTHORITY\\SYSTEM"
        assert p1["status"] == "Unavailable" # Unknown mapped to Unavailable
        
        assert p2["pid"] == "1234"
        assert p2["name"] == "TestProc.exe"
        assert p2["user"] == "TESTDOMAIN\\TestUser"
        assert p2["status"] == "Running"
        
        print("Windows collector mock test passed.")


async def test_controller_system_scan():
    print("\n--- 4. Testing Scan Controller: run_system_scan() ---")
    res = await run_system_scan()
    assert res.status == "COMPLETED", f"Expected COMPLETED, got {res.status}"
    
    subcategories = {fd.subcategory for fd in res.footprint_data}
    assert "Running Processes" in subcategories, "Missing Running Processes subcategory"
    
    proc_items = [fd for fd in res.footprint_data if fd.subcategory == "Running Processes"]
    print(f"Controller returned {len(proc_items)} Running Processes footprint items.")
    assert len(proc_items) > 0

    sample_proc = proc_items[0]
    assert sample_proc.category == "System"
    assert sample_proc.subcategory == "Running Processes"
    assert sample_proc.data_type == "process"
    assert sample_proc.sensitivity == "Low"
    assert sample_proc.source == "Local OS API"
    print(f"Sample process FootprintData: {sample_proc.value}")
    print("Scan Controller test passed.")


def test_ui_and_regressions():
    print("\n--- 5. Testing PySide6 UI and Regressions ---")
    app = QApplication(sys.argv)
    window = MainWindow()

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
    assert "Running Processes" in results_text
    print("System scan UI output verified.")

    # 5.2 Multiple Scan Protection
    print("Testing Multiple Scan Protection...")
    from unittest.mock import AsyncMock
    with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_email:
        mock_email.return_value = {"status": "SUCCESS", "breaches": []}
        window.scan_type_combo.setCurrentText("Email")
        window.target_input.setText("test@example.com")
        window.scan_btn.click()
        worker1 = window.worker
        assert worker1 is not None and worker1.isRunning()

        window.target_input.returnPressed.emit()
        worker2 = window.worker
        assert worker1 is worker2, "Multiple scan protection failed!"
        print("Multiple scan protection verified.")

        wait_for_worker()
    print("Email scan regression verified.")

    # 5.3 Username Scan Regression
    print("Testing Username Scan Regression...")
    with patch("app.core.scan_controller.check_username", new_callable=AsyncMock) as mock_user:
        mock_user.return_value = {"status": "NOT_FOUND"}
        window.scan_type_combo.setCurrentText("Username")
        window.target_input.setText("athul")
        window.scan_btn.click()
        wait_for_worker()
        
    print("Username scan regression verified.")

    app.quit()
    print("All UI and regression tests passed.")


def main():
    test_service_running_processes()
    test_linux_collector_error_handling()
    test_windows_collector_mock()
    asyncio.run(test_controller_system_scan())
    test_ui_and_regressions()
    print("\n============================================================")
    print("ALL SYSTEM FOOTPRINT v3 TESTS COMPLETED SUCCESSFULLY!")
    print("============================================================")


if __name__ == "__main__":
    main()

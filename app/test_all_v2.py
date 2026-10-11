import sys
import os
import asyncio
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow

def run_tests():
    app = QApplication(sys.argv)
    window = MainWindow()
    
    # Switch to Public Lookup where our tools are
    window.sidebar.setCurrentRow(2)
    
    # Test 2: System Scan
    window.sidebar.setCurrentRow(1) # My Footprint page
    window.sys_scan_btn.click()
    while window.worker and not window.worker.isFinished():
        app.processEvents()
        time.sleep(0.1)
    if window.worker:
        window.worker.wait()
    app.processEvents()
    
    results = window.sys_results_area.toPlainText()
    if "System API" in results and "Linux" in results:
        print("Test 2: System scan passed")
    else:
        print(f"Test 2: System scan failed. Results: {results}")

    # Test 3 & 6: Email regression and multi-scan protection
    window.sidebar.setCurrentRow(2)
    window.scan_type_combo.setCurrentText("Email")
    window.target_input.setText("test@example.com")
    window.scan_btn.click()
    
    worker1 = window.worker
    if worker1 is None:
        print("Worker1 is None!")
    
    window.target_input.returnPressed.emit()
    worker2 = window.worker
    
    if worker1 is worker2 and worker1 is not None:
        print("Test 6: Multiple scan protection passed")
    else:
        print("Test 6: Multiple scan protection failed")

    while window.worker and not window.worker.isFinished():
        app.processEvents()
        time.sleep(0.1)
    if window.worker:
        window.worker.wait()
    app.processEvents()

    res3 = window.results_area.toPlainText()
    if "=== FINDINGS ===" in res3:
        print("Test 3: Email regression passed")
    else:
        print(f"Test 3: Email regression failed. Results: {res3}")

    app.quit()

if __name__ == "__main__":
    run_tests()

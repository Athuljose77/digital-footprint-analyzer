import sys
import os
import asyncio

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow

def test_app():
    app = QApplication(sys.argv)
    window = MainWindow()
    
    # Switch to Public Lookup
    window.sidebar.setCurrentRow(2)
    
    # Enter target
    window.target_input.setText("testuser")
    
    # Start first scan
    window.target_input.returnPressed.emit()
    worker1 = window.worker
    
    if worker1 and worker1.isRunning():
        print("First scan started.")
    
    # Try to start second scan immediately
    window.target_input.returnPressed.emit()
    worker2 = window.worker
    
    if worker1 is worker2:
        print("Second scan was correctly ignored.")
    else:
        print("BUG: Second scan replaced the first worker!")
    
    # Let the app run a little bit to see if it crashes
    import time
    time.sleep(1)
    
    print("Test finished successfully.")
    
    # Exit gracefully
    app.quit()

if __name__ == "__main__":
    test_app()

import sys
import os

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

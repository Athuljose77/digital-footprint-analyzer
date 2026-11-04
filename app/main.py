import sys
import os

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from app.ui.main_window import MainWindow
from app.ui.theme import apply_theme, is_dark


def main():
    app = QApplication(sys.argv)

    # The packaging smoke test starts the real window and exits on the first
    # event-loop turn. It catches missing resources/plugins without hanging CI.
    smoke_test = "--smoke-test" in sys.argv[1:]

    # Apply the saved theme before the first window is built, so the app
    # never flashes the wrong colors. MainWindow re-applies it afterwards,
    # which is what makes runtime switching work.
    from PySide6.QtCore import QSettings
    settings = QSettings("DigitalFootprintAnalyzer", "Preferences")
    theme_mode = str(settings.value("theme_mode", "dark")).strip().lower()
    high_contrast = settings.value("high_contrast_selection", True, type=bool)
    font_scale = int(settings.value("font_scale", 13))
    # "system" follows the OS preference; the window resolves the same value,
    # so an initial guess here is enough to avoid a light flash on dark hosts.
    if theme_mode == "dark":
        dark = True
    elif theme_mode == "light":
        dark = False
    else:
        palette = app.palette()
        dark = palette.color(palette.ColorRole.Window).value() < 128
    apply_theme(app, dark=dark, high_contrast=high_contrast,
                font_scale=font_scale)

    window = MainWindow()
    window.show()
    if smoke_test:
        QTimer.singleShot(0, app.quit)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

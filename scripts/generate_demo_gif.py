#!/usr/bin/env python3
"""Generate the README walkthrough GIF from the real demo-mode screens.

The frames are rendered offscreen from synthetic demo data. Pillow is a
development-only dependency for this script; install it with
``pip install pillow``. The application does not need it.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image
from PySide6.QtWidgets import QApplication

from app.core.history import ScanHistoryStore
from app.core.remediation.store import ActionStateStore
from app.ui.main_window import MainWindow

OUTPUT = ROOT / "docs" / "assets" / "demo-mode.gif"
FRAME_WIDTH = 900
FRAME_DURATION_MS = 2200


def capture_window(window, app, path):
    app.processEvents()
    app.processEvents()
    pixmap = window.grab()
    if not pixmap.save(str(path), "PNG"):
        raise RuntimeError(f"Could not save frame: {path}")


def main() -> None:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])

    with tempfile.TemporaryDirectory(prefix="dfa-gif-") as tmp:
        window = MainWindow()
        window.resize(1120, 740)
        window.history_store = ScanHistoryStore(os.path.join(tmp, "history.db"))
        window.action_store = ActionStateStore(os.path.join(tmp, "actions.db"))
        window.history_page.set_store(window.history_store)
        window.current_theme = "dark"
        window.apply_theme()
        window.show()
        window.load_demo_scan()

        frame_paths = []
        for name, page in (
            ("home", "home"),
            ("assessment", "assessment"),
            ("evidence", "evidence"),
            ("actions", "actions"),
        ):
            window.show_page(page)
            path = Path(tmp) / f"{name}.png"
            capture_window(window, app, path)
            frame_paths.append(path)

        window.close()

        images = []
        for path in frame_paths:
            image = Image.open(path).convert("RGB")
            height = round(image.height * FRAME_WIDTH / image.width)
            images.append(image.resize(
                (FRAME_WIDTH, height), Image.Resampling.LANCZOS))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(
        OUTPUT,
        save_all=True,
        append_images=images[1:],
        duration=FRAME_DURATION_MS,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

"""Application theme: light report output plus a dark application theme.

The desktop UI follows the dark dashboard reference by default. All report
HTML reads its colors through R() so the same formatters render correctly
in both themes. Tests run with the light theme (the default) unless they
explicitly enable dark mode.
"""

# Light values are the long-standing report colors and must stay exactly as
# they were so existing output is unchanged unless dark mode is enabled.
LIGHT_REPORT = {
    "text": "#24292e",
    "text_alt": "#333",
    "muted": "#586069",
    "faint": "#888",
    "faint_alt": "#959da5",
    "faint_meta": "#6a737d",
    "subtle": "#666",
    "subtle_alt": "#555",
    "chip_text": "#444d56",
    "black_text": "#000",
    "white": "#ffffff",
    "panel_bg": "#f8f9fa",
    "panel_bg_alt": "#f6f8fa",
    "panel_border": "#e1e4e8",
    "panel_border_alt": "#e9ecef",
    "dotted_border": "#b1b7c0",
    "card_bg": "#fbfcfd",
    "card_bg_concern_high": "#fff8f8",
    "card_bg_concern_med": "#fffbf5",
    "info_bg": "#f1f8ff",
    "ok_text": "#22863a",
    "ok_bg": "#e6f4ea",
    "ok_border": "#b7e0c3",
    "warn_text": "#b04300",
    "warn_bg": "#fff5e6",
    "warn_border": "#f0c48c",
    "err_text": "#cb2431",
    "err_bg": "#ffeef0",
    "err_border": "#f5b5ba",
    "err_text_strong": "#86181d",
    "danger_header": "#d9534f",
    "sensitive_bg": "#fff8f8",
    "sensitive_border": "#f5c6cb",
    "sensitive_text": "#721c24",
    "header_accent": "#1e3799",
    "link": "#0366d6",
    "empty_box_bg": "#2b2b2b",
    "empty_box_text": "#abb2bf",
    "empty_box_heading": "#98c379",
    "empty_box_muted": "#7f848e",
    # Solid badge fills with white text read well on either theme.
    "sev_critical": "#d73a49",
    "sev_high": "#d73a49",
    "sev_medium": "#e36209",
    "sev_low": "#005cc5",
    "sev_info": "#0366d6",
    "chart_medium": "#e3b341",
}

DARK_REPORT = {
    "text": "#d7dee5",
    "text_alt": "#d7dee5",
    "muted": "#93a0ad",
    "faint": "#75808c",
    "faint_alt": "#75808c",
    "faint_meta": "#75808c",
    "subtle": "#75808c",
    "subtle_alt": "#8b98a5",
    "chip_text": "#93a0ad",
    "black_text": "#d7dee5",
    "white": "#ffffff",
    "panel_bg": "#111a22",
    "panel_bg_alt": "#161e26",
    "panel_border": "#24333f",
    "panel_border_alt": "#24333f",
    "dotted_border": "#3a4a56",
    "card_bg": "#121a22",
    "card_bg_concern_high": "#241318",
    "card_bg_concern_med": "#221a10",
    "info_bg": "#0e2231",
    "ok_text": "#4ade80",
    "ok_bg": "#0d2818",
    "ok_border": "#1d4d33",
    "warn_text": "#fbbf24",
    "warn_bg": "#2a1f0d",
    "warn_border": "#6b4d1a",
    "err_text": "#f87171",
    "err_bg": "#2b1218",
    "err_border": "#6e2b31",
    "err_text_strong": "#fca5a5",
    "danger_header": "#f87171",
    "sensitive_bg": "#251417",
    "sensitive_border": "#6e2b31",
    "sensitive_text": "#fca5a5",
    "header_accent": "#7dd3fc",
    "link": "#2dd4bf",
    "empty_box_bg": "#2b2b2b",
    "empty_box_text": "#abb2bf",
    "empty_box_heading": "#98c379",
    "empty_box_muted": "#7f848e",
    "sev_critical": "#d73a49",
    "sev_high": "#d73a49",
    "sev_medium": "#e36209",
    "sev_low": "#005cc5",
    "sev_info": "#0366d6",
    "chart_medium": "#e3b341",
}

assert set(LIGHT_REPORT) == set(DARK_REPORT), "theme maps diverged"

_state = {"dark": False}


def set_dark_theme(enabled=True):
    """Select the report color map. Tests must reset this after use."""
    _state["dark"] = bool(enabled)


def is_dark():
    return _state["dark"]


def R(key):
    """Current report color for key (light unless dark mode enabled)."""
    active = DARK_REPORT if _state["dark"] else LIGHT_REPORT
    return active[key]


DARK_QSS = """
QMainWindow, QWidget#qt_scrollarea_viewport { background-color: #0d1319; }
QWidget { color: #d7dee5; }
QLabel { color: #d7dee5; background: transparent; }
QListWidget {
    background-color: #0d1319;
    border: none;
    outline: 0;
    font-size: 13px;
}
QListWidget::item { padding: 10px 12px; color: #93a0ad; }
QListWidget::item:selected {
    background-color: #16232d;
    color: #2dd4bf;
    border-left: 3px solid #2dd4bf;
    font-weight: bold;
}
QTabWidget::pane { border: 1px solid #24333f; background: #0d1319; }
QTabBar::tab {
    background: #111a22;
    color: #93a0ad;
    padding: 8px 16px;
    border: 1px solid #24333f;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #16232d; color: #2dd4bf; }
QPushButton {
    background-color: #16232d;
    color: #d7dee5;
    border: 1px solid #2a3a45;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton:hover { background-color: #1c2c38; border-color: #2dd4bf; }
QPushButton:pressed { background-color: #101820; }
QPushButton:disabled { color: #5b6672; background-color: #111a22; }
QLineEdit, QComboBox {
    background-color: #0d1319;
    color: #d7dee5;
    border: 1px solid #2a3a45;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #14b8a6;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #2dd4bf; }
QComboBox QAbstractItemView {
    background-color: #111a22;
    color: #d7dee5;
    selection-background-color: #14b8a6;
    selection-color: #062a26;
}
QTextEdit, QTextBrowser {
    background-color: #0d1319;
    color: #d7dee5;
    border: 1px solid #24333f;
    selection-background-color: #14b8a6;
    selection-color: #062a26;
}
QTableWidget {
    background-color: #0d1319;
    color: #d7dee5;
    gridline-color: #1c2833;
    border: 1px solid #24333f;
    selection-background-color: #14b8a6;
    selection-color: #062a26;
}
QHeaderView::section {
    background-color: #111a22;
    color: #93a0ad;
    border: none;
    padding: 6px;
    font-weight: bold;
}
QScrollBar:vertical, QScrollBar:horizontal { background: #0d1319; border: none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #2a3a45;
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}
QScrollBar::handle:hover { background: #14b8a6; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QToolTip { background-color: #111a22; color: #d7dee5; border: 1px solid #2a3a45; }
QDialog { background-color: #0d1319; }
QFrame { color: #d7dee5; }
"""


def apply_dark_theme(app):
    """Apply the dark Fusion palette plus widget stylesheet to the app."""
    from PySide6.QtGui import QColor, QPalette

    app.setStyle("Fusion")
    palette = QPalette()
    base = QColor("#0d1319")
    panel = QColor("#111a22")
    text = QColor("#d7dee5")
    muted = QColor("#93a0ad")
    accent = QColor("#14b8a6")
    palette.setColor(QPalette.Window, base)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, base)
    palette.setColor(QPalette.AlternateBase, panel)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, QColor("#16202a"))
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, QColor("#f87171"))
    palette.setColor(QPalette.Highlight, accent)
    palette.setColor(QPalette.HighlightedText, QColor("#062a26"))
    palette.setColor(QPalette.ToolTipBase, panel)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.PlaceholderText, muted)
    palette.setColor(QPalette.Link, QColor("#2dd4bf"))
    palette.setColor(QPalette.LinkVisited, QColor("#2dd4bf"))
    disabled = QColor("#5b6672")
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, disabled)
    app.setPalette(palette)
    app.setStyleSheet(DARK_QSS)
    set_dark_theme(True)

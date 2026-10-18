"""Application theme: color tokens, application chrome, and theme switching.

This module is the single source of truth for every color in the desktop UI.
Report HTML reads colors through R(); widget chrome is built by build_qss()
from the same token maps, so light and dark can never drift apart and no
color is hardcoded in main_window.py.

The desktop UI follows the dark dashboard reference by default. Tests run
with the light theme unless they explicitly enable dark mode.
"""

# Light values are the long-standing report colors and must stay exactly as
# they were so existing output is unchanged unless dark mode is enabled.
LIGHT_REPORT = {
    "text": "#24292e",
    "text_alt": "#333",
    "muted": "#586069",
    # Chrome accent (sidebar/hero/card borders and buttons) is brand teal in
    # both themes. It is deliberately independent of "link", which follows the
    # report palette and differs per theme.
    "accent": "#2dd4bf",
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
    "accent": "#2dd4bf",
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

# The module starts on the light report palette. A MainWindow switches
# this to the saved user preference when one is built; tests and report
# formatting rely on the light default unless they opt into dark.
DEFAULT_DARK = False

_state = {"dark": DEFAULT_DARK}


def set_dark_theme(enabled=True):
    """Select the report color map. Tests must reset this after use."""
    _state["dark"] = bool(enabled)


def is_dark():
    return _state["dark"]


def R(key):
    """Current report color for key (light unless dark mode enabled)."""
    active = DARK_REPORT if _state["dark"] else LIGHT_REPORT
    return active[key]


# Application chrome values. These describe window surfaces rather than
# report content, so they are resolved per theme instead of through R().
_CHROME = {
    True: {
        "app_bg": "#0d1319",
        "panel_bg": "#111a22",
        "button_bg": "#16232d",
        "button_hover": "#1c2c38",
        "button_press": "#101820",
        "selected_bg": "#16232d",
        "scroll_handle": "#2a3a45",
        "disabled": "#5b6672",
        "tooltip_bg": "#111a22",
    },
    False: {
        "app_bg": "#ffffff",
        "panel_bg": "#f6f8fa",
        "button_bg": "#f6f8fa",
        "button_hover": "#e1e4e8",
        "button_press": "#e9ecef",
        "selected_bg": "#e1e4e8",
        "scroll_handle": "#c1c7ce",
        "disabled": "#959da5",
        "tooltip_bg": "#fffffe",
    },
}

# High-contrast selection colors (issue: white-on-white selection blocks).
HIGH_CONTRAST_SELECTION = ("#2563eb", "#ffffff")
STANDARD_SELECTION = ("#14b8a6", "#062a26")


def build_qss(dark=True, high_contrast=True, font_scale=13):
    """Build the application stylesheet for one theme from token values.

    Every color is taken from the token maps or the chrome table above so
    the light and dark themes stay in sync and no literal lives in a widget.
    """
    c = _CHROME[dark]
    tokens = DARK_REPORT if dark else LIGHT_REPORT
    text = tokens["text"]
    muted = tokens["muted"]
    border = tokens["panel_border"]
    accent = tokens["accent"]
    accent_text = tokens["link"]
    sel_bg, sel_fg = HIGH_CONTRAST_SELECTION if high_contrast else STANDARD_SELECTION
    # Font scaling is opt-in: at the default scale nothing is emitted, so the
    # shipped appearance is exactly what it was before the setting existed.
    scale_qss = ""
    if font_scale != 13:
        scale_qss = (
            "\nQLabel, QPushButton, QLineEdit, QComboBox, QTextEdit, "
            "QTextBrowser, QTableWidget { font-size: %dpx; }" % font_scale
        )
    return f"""
QMainWindow, QWidget#qt_scrollarea_viewport {{ background-color: {c["app_bg"]}; }}
QWidget {{ color: {text}; }}
QLabel {{ color: {text}; background: transparent; }}
QListWidget {{
    background-color: {c["app_bg"]};
    border: none;
    outline: 0;
    font-size: 13px;
}}
QListWidget::item {{ padding: 10px 12px; color: {muted}; }}
QListWidget::item:hover {{ background-color: {c["button_hover"]}; color: {text}; }}
QListWidget::item:selected {{
    background-color: {c["selected_bg"]};
    color: {accent_text};
    border-left: 3px solid {accent};
    font-weight: bold;
}}
QTabWidget::pane {{ border: 1px solid {border}; background: {c["app_bg"]}; }}
QTabBar::tab {{
    background: {c["panel_bg"]};
    color: {muted};
    padding: 8px 16px;
    border: 1px solid {border};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}}
QTabBar::tab:selected {{ background: {c["selected_bg"]}; color: {accent_text}; }}
QPushButton {{
    background-color: {c["button_bg"]};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{ background-color: {c["button_hover"]}; border-color: {accent}; }}
QPushButton:pressed {{ background-color: {c["button_press"]}; }}
QPushButton:disabled {{ color: {c["disabled"]}; background-color: {c["panel_bg"]}; }}
QLineEdit, QComboBox {{
    background-color: {c["app_bg"]};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {accent}; }}
QComboBox QAbstractItemView {{
    background-color: {c["panel_bg"]};
    color: {text};
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QTextEdit, QTextBrowser {{
    background-color: {c["app_bg"]};
    color: {text};
    border: 1px solid {border};
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QTableWidget {{
    background-color: {c["app_bg"]};
    color: {text};
    gridline-color: {border};
    border: 1px solid {border};
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QHeaderView::section {{
    background-color: {c["panel_bg"]};
    color: {muted};
    border: none;
    padding: 6px;
    font-weight: bold;
}}
QScrollBar:vertical, QScrollBar:horizontal {{ background: {c["app_bg"]}; border: none; }}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: {c["scroll_handle"]};
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}}
QScrollBar::handle:hover {{ background: {accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QToolTip {{ background-color: {c["tooltip_bg"]}; color: {text}; border: 1px solid {border}; }}
QDialog {{ background-color: {c["app_bg"]}; }}
QFrame {{ color: {text}; }}
QGroupBox {{ border: 1px solid {border}; border-radius: 6px; margin-top: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; color: {muted}; }}
QCheckBox, QRadioButton {{ color: {text}; spacing: 6px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 15px; height: 15px; }}
QScrollArea {{ background: {c["app_bg"]}; border: none; }}
{scale_qss}
"""


# Kept as module constants so existing callers and tests keep working.
DARK_QSS = build_qss(dark=True)
LIGHT_QSS = build_qss(dark=False)


def apply_theme(app, dark=True, high_contrast=True, font_scale=13, target=None):
    """Apply the Fusion palette and stylesheet for one theme.

    Args:
        app: the QApplication, used for the palette.
        dark: select the dark token map when True.
        high_contrast: use the high-contrast selection colors.
        font_scale: base text size in px; 13 emits no font-size rule.
        target: widget that receives the stylesheet. Defaults to the whole
            application, which is right at startup. A MainWindow passes
            itself so a theme switch restyles one window instead of every
            live widget in the process, which is what makes switching cheap.
    """
    from PySide6.QtGui import QColor, QPalette

    tokens = DARK_REPORT if dark else LIGHT_REPORT
    c = _CHROME[dark]
    sel_bg, sel_fg = HIGH_CONTRAST_SELECTION if high_contrast else STANDARD_SELECTION

    app.setStyle("Fusion")
    palette = QPalette()
    base = QColor(c["app_bg"])
    panel = QColor(c["panel_bg"])
    text = QColor(tokens["text"])
    muted = QColor(tokens["muted"])
    palette.setColor(QPalette.Window, base)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, base)
    palette.setColor(QPalette.AlternateBase, panel)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, QColor(c["button_bg"]))
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.BrightText, QColor(tokens["err_text"]))
    palette.setColor(QPalette.Highlight, QColor(sel_bg))
    palette.setColor(QPalette.HighlightedText, QColor(sel_fg))
    palette.setColor(QPalette.ToolTipBase, panel)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.PlaceholderText, muted)
    palette.setColor(QPalette.Link, QColor(tokens["link"]))
    palette.setColor(QPalette.LinkVisited, QColor(tokens["link"]))
    disabled = QColor(c["disabled"])
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, disabled)
    app.setPalette(palette)
    qss = build_qss(dark=dark, high_contrast=high_contrast,
                    font_scale=font_scale)
    (target if target is not None else app).setStyleSheet(qss)
    set_dark_theme(dark)
    return dark


def apply_dark_theme(app, high_contrast=True, font_scale=13):
    """Apply the dark Fusion palette plus widget stylesheet to the app."""
    return apply_theme(app, dark=True, high_contrast=high_contrast,
                       font_scale=font_scale)


def apply_light_theme(app, high_contrast=True, font_scale=13):
    """Apply the light Fusion palette plus widget stylesheet to the app."""
    return apply_theme(app, dark=False, high_contrast=high_contrast,
                       font_scale=font_scale)

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
# The dark values carry the refined dashboard palette; the light values are
# their equivalents so a theme switch stays visually symmetric.
_CHROME = {
    True: {
        "app_bg": "#0d1319",
        "sidebar_bg": "#0a111a",
        "nav_item": "#7e9bb5",
        "nav_item_hover_bg": "#111e2d",
        "nav_selected_bg": "#0e2736",
        "nav_selected_border": "#1a4954",
        "panel_bg": "#111a22",
        "panel_border": "#1e3148",
        "tab_bg": "#0f1c2b",
        "tab_selected_bg": "#15273b",
        "button_bg": "#121f2f",
        "button_hover": "#182b40",
        "button_hover_text": "#ffffff",
        "button_press": "#0a121c",
        "disabled": "#5b6672",
        "disabled_bg": "#0e1722",
        "disabled_border": "#182736",
        "input_bg": "#0a121c",
        "input_border": "#1d334d",
        "popup_bg": "#0e1a27",
        "table_bg": "#0a121c",
        "gridline": "#142436",
        "header_bg": "#0f1c2b",
        "scroll_bg": "#0a111a",
        "scroll_handle": "#1d334d",
        "tooltip_bg": "#0e1a27",
    },
    False: {
        "app_bg": "#ffffff",
        "sidebar_bg": "#ffffff",
        "nav_item": "#586069",
        "nav_item_hover_bg": "#f0f3f6",
        "nav_selected_bg": "#e3f5f2",
        "nav_selected_border": "#9adfd6",
        "panel_bg": "#f6f8fa",
        "panel_border": "#e1e4e8",
        "tab_bg": "#f6f8fa",
        "tab_selected_bg": "#e3f5f2",
        "button_bg": "#f6f8fa",
        "button_hover": "#eef1f4",
        "button_hover_text": "#24292e",
        "button_press": "#e9ecef",
        "disabled": "#959da5",
        "disabled_bg": "#f6f8fa",
        "disabled_border": "#e1e4e8",
        "input_bg": "#ffffff",
        "input_border": "#d0d7de",
        "popup_bg": "#ffffff",
        "table_bg": "#ffffff",
        "gridline": "#eaeef2",
        "header_bg": "#f6f8fa",
        "scroll_bg": "#f0f3f6",
        "scroll_handle": "#c1c7ce",
        "tooltip_bg": "#fffffe",
    },
}

def _rgba(hex_color, alpha):
    """Convert a #rrggbb token to an rgba() string for translucent fills."""
    h = hex_color.lstrip("#")
    return "rgba(%d, %d, %d, %s)" % (
        int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), alpha)


def accent_soft(alpha=0.08):
    """Translucent accent fill, used behind accent-coloured buttons."""
    return _rgba(R("accent"), alpha)


def on_accent():
    """Text color placed on top of a solid accent fill (dark, both themes)."""
    return _CHROME[is_dark()]["button_press"] if is_dark() else "#062a26"


def panel_hover():
    """Slightly lifted panel background used on hover."""
    return _CHROME[is_dark()]["nav_item_hover_bg"] if is_dark() \
        else _CHROME[False]["nav_item_hover_bg"]


# Token names a widget stylesheet template may use. Every value resolves
# through this module, so no widget carries a literal color and a theme switch
# restyles it by re-rendering the same template.
THEME_TEMPLATE_TOKENS = (
    "panel_bg",
    "panel_bg_alt",
    "panel_border",
    "text",
    "muted",
    "faint",
    "accent",
    "accent_soft",
    "on_accent",
    "panel_hover",
)


def render_template(template):
    """Resolve a themed-widget stylesheet template against the active theme."""
    return template.format(
        panel_bg=R("panel_bg"),
        panel_bg_alt=R("panel_bg_alt"),
        panel_border=R("panel_border"),
        text=R("text"),
        muted=R("muted"),
        faint=R("faint"),
        accent=R("accent"),
        accent_soft=accent_soft(),
        on_accent=on_accent(),
        panel_hover=panel_hover(),
    )


# High-contrast selection colors (issue: white-on-white selection blocks).
HIGH_CONTRAST_SELECTION = ("#2563eb", "#ffffff")
STANDARD_SELECTION = ("#14b8a6", "#062a26")


def build_qss(dark=True, high_contrast=True, font_scale=13):
    """Build the application stylesheet for one theme from token values.

    Every color comes from the token maps or the chrome table, so the light
    and dark themes stay in sync and no literal lives in a widget.
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
    background-color: {c["sidebar_bg"]};
    border: none;
    outline: 0;
    font-size: 13px;
    padding: 6px 0;
}}
QListWidget::item {{
    padding: 10px 14px;
    color: {c["nav_item"]};
    border-radius: 8px;
    margin: 3px 6px;
}}
QListWidget::item:hover {{ background-color: {c["nav_item_hover_bg"]}; color: {text}; }}
QListWidget::item:selected {{
    background-color: {c["nav_selected_bg"]};
    color: {accent_text};
    border: 1px solid {c["nav_selected_border"]};
    font-weight: bold;
}}
QTabWidget::pane {{
    border: 1px solid {c["panel_border"]};
    background: {c["app_bg"]};
    border-radius: 6px;
}}
QTabBar::tab {{
    background: {c["tab_bg"]};
    color: {c["nav_item"]};
    padding: 8px 18px;
    border: 1px solid {c["panel_border"]};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {c["tab_selected_bg"]};
    color: {accent_text};
    border-bottom: 2px solid {accent};
    font-weight: bold;
}}
QPushButton {{
    background-color: {c["button_bg"]};
    color: {text};
    border: 1px solid {tokens["panel_border"]};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{
    background-color: {c["button_hover"]};
    border-color: {accent};
    color: {c["button_hover_text"]};
}}
QPushButton:pressed {{ background-color: {c["button_press"]}; }}
QPushButton:disabled {{
    color: {c["disabled"]};
    background-color: {c["disabled_bg"]};
    border-color: {c["disabled_border"]};
}}
QLineEdit, QComboBox {{
    background-color: {c["input_bg"]};
    color: {text};
    border: 1px solid {c["input_border"]};
    border-radius: 6px;
    padding: 6px 12px;
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {accent}; }}
QComboBox QAbstractItemView {{
    background-color: {c["popup_bg"]};
    color: {text};
    border: 1px solid {c["input_border"]};
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QTextEdit, QTextBrowser {{
    background-color: {c["app_bg"]};
    color: {text};
    border: 1px solid {c["input_border"]};
    border-radius: 6px;
    selection-background-color: {sel_bg};
    selection-color: {sel_fg};
}}
QTableWidget {{
    background-color: {c["table_bg"]};
    color: {text};
    gridline-color: {c["gridline"]};
    border: 1px solid {c["input_border"]};
    border-radius: 6px;
    selection-background-color: {c["nav_selected_bg"]};
    selection-color: {accent};
}}
QHeaderView::section {{
    background-color: {c["header_bg"]};
    color: {c["nav_item"]};
    border: none;
    padding: 8px 8px;
    font-weight: bold;
}}
QScrollBar:vertical, QScrollBar:horizontal {{ background: {c["scroll_bg"]}; border: none; }}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: {c["scroll_handle"]};
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}}
QScrollBar::handle:hover {{ background: {accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QToolTip {{ background-color: {c["tooltip_bg"]}; color: {text}; border: 1px solid {c["input_border"]}; }}
QDialog {{ background-color: {c["app_bg"]}; }}
QFrame {{ color: {text}; }}
QGroupBox {{ border: 1px solid {c["panel_border"]}; border-radius: 6px; margin-top: 10px; }}
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

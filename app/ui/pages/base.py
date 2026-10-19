"""Shared building blocks for the assessment, evidence, actions, and history pages.

Each page collects ``(widget, template)`` pairs while it builds. MainWindow
registers those pairs with its existing themed-widget list, so a theme switch
restyles the new pages through exactly the same mechanism as the rest of the
window: one token map, one render function.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.ui import theme

CARD_TEMPLATE = (
    "background-color: {panel_bg_alt}; border: 1px solid {panel_border}; "
    "border-radius: 10px;"
)

PRIMARY_BUTTON_TEMPLATE = (
    "QPushButton {{ background-color: {accent}; color: {on_accent}; "
    "border: none; border-radius: 6px; padding: 6px 14px; font-weight: bold; }} "
    "QPushButton:hover {{ background-color: {accent_soft}; color: {accent}; }} "
    "QPushButton:disabled {{ background-color: {panel_bg}; color: {muted}; }}"
)

SUBTLE_BUTTON_TEMPLATE = (
    "QPushButton {{ background-color: {panel_bg}; color: {text}; "
    "border: 1px solid {panel_border}; border-radius: 6px; padding: 5px 12px; }} "
    "QPushButton:hover {{ border-color: {accent}; color: {accent}; }} "
    "QPushButton:disabled {{ color: {muted}; }}"
)

FIELD_TEMPLATE = (
    "QLineEdit, QComboBox {{ background-color: {panel_bg}; color: {text}; "
    "border: 1px solid {panel_border}; border-radius: 6px; padding: 5px 8px; }} "
    "QLineEdit:focus, QComboBox:focus {{ border-color: {accent}; }}"
)

TABLE_TEMPLATE = (
    "QTableWidget {{ background-color: {panel_bg}; color: {text}; "
    "border: 1px solid {panel_border}; border-radius: 8px; gridline-color: {panel_border}; }} "
    "QHeaderView::section {{ background-color: {panel_bg_alt}; color: {muted}; "
    "border: none; border-bottom: 1px solid {panel_border}; padding: 6px; }} "
    "QTableWidget::item:selected {{ background-color: {accent_soft}; color: {accent}; }}"
)


class ThemedPage(QWidget):
    """Base class for the expanded pages."""

    def __init__(self, window=None, parent=None):
        super().__init__(parent)
        self.window = window
        self._themed = []
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(18, 16, 18, 16)
        self._layout.setSpacing(12)

    # -- theming --------------------------------------------------------

    def themed(self, widget, template):
        """Style a widget from a token template and remember the template."""
        widget.setStyleSheet(theme.render_template(template))
        self._themed.append((widget, template))
        return widget

    def themed_widgets(self):
        return list(self._themed)

    def refresh_theme(self):
        """Re-render HTML that resolved colors through R(). Override."""

    # -- construction helpers ------------------------------------------

    def add_header(self, title, subtitle=""):
        self.title_label = QLabel(f"<b>{title}</b>")
        self.title_label.setStyleSheet("font-size: 18px;")
        self._layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setWordWrap(True)
        self.themed(self.subtitle_label, "color: {muted}; font-size: 12px;")
        self._layout.addWidget(self.subtitle_label)
        return self.subtitle_label

    def add_card(self, object_name=None):
        card = QFrame()
        if object_name:
            card.setObjectName(object_name)
        self.themed(card, CARD_TEMPLATE)
        return card

    def button(self, text, primary=True):
        button = QPushButton(text)
        return self.themed(button, PRIMARY_BUTTON_TEMPLATE if primary
                           else SUBTLE_BUTTON_TEMPLATE)

    def note(self, text=""):
        label = QLabel(text)
        label.setWordWrap(True)
        self.themed(label, "color: {muted}; font-size: 11px;")
        return label

    def _row(self, *widgets):
        row = QHBoxLayout()
        row.setSpacing(8)
        for widget in widgets:
            if widget is None:
                row.addStretch()
            else:
                row.addWidget(widget)
        return row


def clear_layout(layout):
    """Remove and delete every child widget of a layout."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        else:
            child = item.layout()
            if child is not None:
                clear_layout(child)


def set_badge(label, text, color):
    """Render a small colored badge inside a label."""
    label.setText(
        f"<span style='background-color: {color}; color: #ffffff; "
        f"border-radius: 4px; padding: 2px 8px; font-weight: bold;'>{text}</span>"
    )


SEVERITY_COLORS = {
    "Critical": "sev_critical",
    "High": "sev_high",
    "Medium": "sev_medium",
    "Low": "sev_low",
    "Info": "sev_info",
}


def severity_color(severity):
    return theme.R(SEVERITY_COLORS.get(str(severity or "Info").capitalize(),
                                       "sev_info"))


def badge_html(text, color):
    return (f"<span style='background-color: {color}; color: #ffffff; "
            f"border-radius: 3px; padding: 1px 6px;'>{text}</span>")


def escape(value):
    from html import escape as _escape

    return _escape(str(value if value is not None else ""))


ALIGN_TOP = Qt.AlignTop | Qt.AlignLeft

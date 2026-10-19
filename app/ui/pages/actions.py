"""Action centre: what to do about the findings, prioritised.

Actions come from app/core/remediation, which maps findings to a fixed set of
remediation templates. The page owns no advice of its own.

The user's own marks (complete / dismissed) are persisted by the window in the
action-state store. This page reports a click; it never decides that an issue
is technically fixed.
"""

from typing import Callable, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.core.remediation import ActionBoard, ActionItem, RemediationPlan
from app.core.remediation.models import COMPLETED, DISMISSED, PENDING
from app.ui import theme
from app.ui.pages.base import (
    CARD_TEMPLATE,
    FIELD_TEMPLATE,
    ThemedPage,
    badge_html,
    escape,
    severity_color,
)

FILTERS = ("All actions", "Pending", "Completed by you", "Dismissed")

_PRIORITY_COLORS = {
    "Critical": "sev_critical",
    "High": "sev_high",
    "Medium": "sev_medium",
    "Low": "sev_low",
}


class ActionCentrePage(ThemedPage):
    """Prioritised remediation list with user-controlled state."""

    def __init__(self, window=None, parent=None):
        super().__init__(window, parent)

        self.board: Optional[ActionBoard] = None
        self.plan: Optional[RemediationPlan] = None
        self.state_handler: Optional[Callable[[str, str], None]] = None

        self.add_header(
            "Action Centre",
            "Steps to reduce the exposure found in the latest scan. Marking "
            "something complete records your own work; it is not a technical "
            "verification that the issue is gone.")

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(FILTERS)
        controls.addWidget(self.filter_combo)
        controls.addStretch(1)
        self._layout.addLayout(controls)
        self.themed(self.filter_combo, FIELD_TEMPLATE)

        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextFormat(Qt.RichText)
        self._layout.addWidget(self.summary_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent;")
        self.cards_host = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_host)
        self.cards_layout.setContentsMargins(0, 0, 8, 0)
        self.cards_layout.setSpacing(10)
        self.cards_layout.addStretch(1)
        scroll.setWidget(self.cards_host)
        self._layout.addWidget(scroll, stretch=1)

        self.privacy_note = self.note(
            "Actions are derived from findings only, so a scan with nothing to "
            "fix produces no advice. State is stored on this device and can be "
            "cleared from the History page.")
        self._layout.addWidget(self.privacy_note)

        self.filter_combo.currentIndexChanged.connect(self.render)

        self.clear()

    # -- data -----------------------------------------------------------

    def clear(self):
        self.board = None
        self.plan = None
        self._render_empty(
            "No actions yet",
            "Run a scan to see what needs attention. Nothing is invented when "
            "there is no scan data.")

    def set_board(self, board: Optional[ActionBoard],
                  plan: Optional[RemediationPlan] = None,
                  state_handler: Optional[Callable[[str, str], None]] = None):
        """Show a plan/board pair, optionally wiring state changes out."""
        self.board = board
        self.plan = plan
        if board is not None and state_handler is not None:
            self.state_handler = state_handler
        self.render()

    def refresh_theme(self):
        self.render()

    # -- rendering ------------------------------------------------------

    def render(self):
        if self.board is None:
            self.clear()
            return

        board = self.board
        items = self._visible_items()
        self.summary_label.setText(self._summary_html())

        self._clear_cards()
        if not items and not board.not_detected:
            self._render_empty("Nothing to do here",
                               board.note or "No findings mapped to an action.")
            return

        if not items and board.not_detected and \
                self.filter_combo.currentText() == FILTERS[0]:
            self._render_empty("Nothing to do here",
                               board.note or "No findings mapped to an action.")

        for item in items:
            self.cards_layout.insertWidget(self.cards_layout.count() - 1,
                                           self._item_card(item))

        if self._show_not_detected():
            header = QLabel("<b>Completed by you — no longer detected</b>")
            header.setStyleSheet("font-size: 13px;")
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, header)
            for item in board.not_detected:
                self.cards_layout.insertWidget(self.cards_layout.count() - 1,
                                               self._item_card(item))

    def _visible_items(self) -> List[ActionItem]:
        board = self.board
        selected = self.filter_combo.currentText()
        items = list(board.items)
        if selected == "Pending":
            return [i for i in items if i.state == PENDING]
        if selected == "Completed by you":
            return [i for i in items if i.state == COMPLETED]
        if selected == "Dismissed":
            return [i for i in items if i.state == DISMISSED]
        return items

    def _show_not_detected(self) -> bool:
        if self.board is None or not self.board.not_detected:
            return False
        return self.filter_combo.currentText() in (FILTERS[0], "Completed by you")

    def _clear_cards(self):
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _render_empty(self, title, body):
        self._clear_cards()
        card = QFrame()
        card.setObjectName("action_empty_card")
        self.themed(card, CARD_TEMPLATE)
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 14, 16, 14)
        heading = QLabel(f"<b>{escape(title)}</b>")
        heading.setStyleSheet("font-size: 14px;")
        box.addWidget(heading)
        body_label = QLabel(escape(body))
        body_label.setWordWrap(True)
        self.themed(body_label, "color: {muted};")
        box.addWidget(body_label)
        self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)

    def _summary_html(self):
        board = self.board
        parts = [f"<b>{board.pending}</b> pending"]
        if board.completed:
            parts.append(f"{board.completed} marked complete by you")
        if board.dismissed:
            parts.append(f"{board.dismissed} dismissed")
        if board.completed_not_verified:
            parts.append(f"{board.completed_not_verified} completed and no "
                         "longer detected")
        muted = theme.R("muted")
        text = f"<span style='color:{muted};'>" + " &nbsp;·&nbsp; ".join(parts) \
            + "</span>"
        if board.note:
            text += f"<br><span style='color:{muted};'>{escape(board.note)}</span>"
        return text

    def _item_card(self, item: ActionItem) -> QFrame:
        action = item.action
        card = QFrame()
        card.setObjectName(f"action_card_{action.action_key}")
        self.themed(card, CARD_TEMPLATE)
        box = QVBoxLayout(card)
        box.setContentsMargins(14, 12, 14, 12)
        box.setSpacing(6)

        muted = theme.R("muted")
        color = theme.R(_PRIORITY_COLORS.get(action.priority, "sev_info"))
        title_row = QHBoxLayout()
        title = QLabel(
            f"{badge_html(escape(action.priority), color)} "
            f"<b style='font-size: 14px;'>{escape(action.title)}</b>")
        title.setTextFormat(Qt.RichText)
        title.setWordWrap(True)
        title_row.addWidget(title, stretch=1)

        state_badge = {
            PENDING: None,
            COMPLETED: theme.R("ok_text"),
            DISMISSED: theme.R("muted"),
        }.get(item.state)
        if state_badge:
            state_label = QLabel(badge_html(escape(item.state), state_badge))
            state_label.setTextFormat(Qt.RichText)
            title_row.addWidget(state_label)
        box.addLayout(title_row)

        meta_parts = [f"Module: {escape(action.module)}",
                      f"Severity: {escape(action.severity)}",
                      f"Evidence: {escape(action.verification)}",
                      f"Confidence: {escape(action.confidence)}"]
        if action.rule_ids:
            meta_parts.append("Rule: " + escape(", ".join(action.rule_ids)))
        meta = QLabel(" &nbsp;·&nbsp; ".join(meta_parts))
        meta.setTextFormat(Qt.RichText)
        meta.setWordWrap(True)
        self.themed(meta, "color: {muted}; font-size: 11px;")
        box.addWidget(meta)

        if action.why_it_matters:
            why = QLabel(f"<i>Why it matters:</i> {escape(action.why_it_matters)}")
            why.setWordWrap(True)
            box.addWidget(why)

        if action.steps:
            steps = QLabel("<ol style='margin-top:2px; margin-bottom:2px;'>"
                           + "".join(f"<li>{escape(step)}</li>"
                                     for step in action.steps)
                           + "</ol>")
            steps.setTextFormat(Qt.RichText)
            steps.setWordWrap(True)
            box.addWidget(steps)

        if action.docs:
            links = " &nbsp;·&nbsp; ".join(
                f"<a href='{escape(doc.url)}' style='color: "
                f"{theme.R('link')};'>{escape(doc.label)}</a>"
                for doc in action.docs)
            link_label = QLabel(links)
            link_label.setTextFormat(Qt.RichText)
            link_label.setWordWrap(True)
            link_label.setOpenExternalLinks(True)
            link_label.setTextInteractionFlags(
                Qt.TextBrowserInteraction | Qt.LinksAccessibleByMouse)
            box.addWidget(link_label)

        if item.status_note:
            note = QLabel(escape(item.status_note))
            note.setWordWrap(True)
            self.themed(note, "color: {muted}; font-size: 11px;")
            box.addWidget(note)
        elif action.note:
            note = QLabel(escape(action.note))
            note.setWordWrap(True)
            self.themed(note, "color: {muted}; font-size: 11px;")
            box.addWidget(note)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        if item.state == PENDING:
            complete = self.button("Mark complete")
            complete.clicked.connect(
                lambda _=False, key=action.action_key: self._set_state(key, COMPLETED))
            buttons.addWidget(complete)
            dismiss = self.button("Dismiss", primary=False)
            dismiss.clicked.connect(
                lambda _=False, key=action.action_key: self._set_state(key, DISMISSED))
            buttons.addWidget(dismiss)
        else:
            reopen = self.button("Reopen", primary=False)
            reopen.clicked.connect(
                lambda _=False, key=action.action_key: self._set_state(key, PENDING))
            buttons.addWidget(reopen)
            if item.state == COMPLETED and not item.present_in_latest_scan:
                forget = self.button("Forget", primary=False)
                forget.clicked.connect(
                    lambda _=False, key=action.action_key: self._set_state(key, "forget"))
                buttons.addWidget(forget)
        buttons.addStretch(1)
        box.addLayout(buttons)
        return card

    # -- state changes --------------------------------------------------

    def _set_state(self, action_key: str, state: str):
        if self.state_handler is not None:
            self.state_handler(action_key, state)
            return
        # No handler wired (for example in a unit test): apply locally so the
        # buttons are still exercised end to end.
        if self.board is None:
            return
        for item in list(self.board.items) + list(self.board.not_detected):
            if item.action.action_key != action_key:
                continue
            if state == "forget":
                self.board.items = [i for i in self.board.items
                                    if i.action.action_key != action_key]
                self.board.not_detected = [
                    i for i in self.board.not_detected
                    if i.action.action_key != action_key]
            else:
                item.state = state
        self.board.pending = sum(1 for i in self.board.items
                                 if i.state == PENDING)
        self.board.completed = sum(1 for i in self.board.items
                                   if i.state == COMPLETED)
        self.board.dismissed = sum(1 for i in self.board.items
                                   if i.state == DISMISSED)
        self.render()

    # -- testing helpers ------------------------------------------------

    def visible_titles(self) -> List[str]:
        return [item.action.title for item in self._visible_items()]

    def pending_count(self) -> int:
        return self.board.pending if self.board else 0

    def card_widgets(self) -> List[QWidget]:
        widgets = []
        for index in range(self.cards_layout.count()):
            widget = self.cards_layout.itemAt(index).widget()
            if isinstance(widget, QFrame) and \
                    widget.objectName().startswith("action_card_"):
                widgets.append(widget)
        return widgets

    def card_titles(self) -> List[str]:
        titles = []
        for card in self.card_widgets():
            for label in card.findChildren(QLabel):
                text = label.text()
                if "<b style='font-size: 14px;'>" in text:
                    titles.append(text.split("<b style='font-size: 14px;'>")[1]
                                  .split("</b>")[0])
        return titles

    def summary_text(self) -> str:
        return self.summary_label.text()

import os
import sys
import html
import platform
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QScrollArea,
    QPushButton, QLabel, QLineEdit, QComboBox, QDialog, QFrame,
    QTextEdit, QTextBrowser, QStackedWidget, QListWidget, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QListWidgetItem, QGroupBox, QButtonGroup, QRadioButton, QCheckBox,
    QGridLayout, QApplication
)
from PySide6.QtCore import Qt, QTimer, QSize, QSettings
from PySide6.QtGui import QColor, QPalette
from app.ui import theme
from app.ui.icons import icon, pixmap
from app.ui.theme import R
from app.ui.workers import ScanWorker
from app.ui.pages import (
    ActionCentrePage,
    AssessmentPage,
    EvidencePage,
    HistoryPage,
)
from app.core import scan_coverage
from app.core.history import HistoryStoreError, ScanHistoryStore
from app.core.remediation import build_plan, plan_with_states
from app.core.remediation.models import COMPLETED, DISMISSED, PENDING
from app.core.remediation.store import ActionStateStore
from app.core.risk import build_risk_summary
from app.services.system_service import (
    DEFAULT_PROCESS_COLLECTOR_MODE,
    PROCESS_COLLECTOR_MODES,
)


# Maximum finding-evidence entries rendered inside a single findings card.
# The complete records remain available in the Collected Evidence view.
FINDING_EVIDENCE_PREVIEW_LIMIT = 10


def flatten_evidence_value(value):
    """Render any evidence value as readable text without Python reprs.

    Nested lists are joined with "; " and mappings become "key: value"
    pairs, so structures such as {"searched": ["a", "b"]} display as
    "searched: a; b" instead of raw Python representation.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        parts = [flatten_evidence_value(v) for v in value]
        return "; ".join(p for p in parts if p)
    if isinstance(value, dict):
        if not value:
            return ""
        return "; ".join(f"{k}: {flatten_evidence_value(v)}" for k, v in value.items())
    return str(value).strip()


def collect_finding_evidence_items(evidence):
    """Normalize finding evidence into a list of non-empty display strings.

    Counting rule: each returned string is one evidence entry. Finding
    evidence is never added to the Collected Evidence count, which is
    defined solely as len(ScanResult.footprint_data), so shared underlying
    data is not counted twice.
    """
    if evidence is None:
        return []
    if isinstance(evidence, list):
        items = []
        for entry in evidence:
            if entry is None:
                continue
            text = flatten_evidence_value(entry)
            if text:
                items.append(text)
        return items
    if isinstance(evidence, dict):
        if not evidence:
            return []
        return [f"{key}: {flatten_evidence_value(value)}" for key, value in evidence.items()]
    text = str(evidence).strip()
    return [text] if text else []


# Finding types that describe scan coverage rather than exposures. They are
# rendered in a dedicated "Coverage & limitations" section, never mixed in
# with concern/observation cards.
COVERAGE_FINDING_TYPES = frozenset({
    "Scan Coverage",
    "Unavailable Sources",
    "Scan Warnings",
    "Scan Limitation",
})

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")

SEVERITY_GUIDANCE = {
    "Critical": "Critical · needs attention",
    "High": "High · worth reviewing",
    "Medium": "Medium · worth a look",
    "Low": "Low · for awareness",
    "Info": "Info · for awareness",
}

SCAN_STATUS_GUIDANCE = {
    "COMPLETED": "Finished — all modules completed",
    "PARTIAL": "Finished with gaps — see limitations below",
    "ERROR": "Failed — the scan did not complete",
}

# Report module order/labels are owned by the shared coverage module so the
# dashboard, the exposure score, and scan history always agree on what ran.
MODULE_LABELS = scan_coverage.MODULE_LABELS


def summarize_full_scan(result):
    """Build a read-only display summary for a Full Scan result.

    Module states come from the shared coverage derivation, which uses the
    authoritative per-module statuses when the scan controller recorded them
    and otherwise derives them from result signals. Never invents statistics:
    every row traces back to result data.
    """
    findings = list(result.findings or [])
    # Display vocabulary. The shared derivation distinguishes "this module
    # could not run on this platform" from "this module ran with limits";
    # the dashboard has always rendered both as a limited module with an
    # explanatory note, so the state is mapped back for display only. The
    # precise state still drives scoring, confidence, and history.
    modules = [dict(row) for row in scan_coverage.derive_scan_coverage(result)]
    for row in modules:
        if row.get("state") == scan_coverage.UNAVAILABLE:
            row["state"] = scan_coverage.LIMITED

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = (f.severity or "Info").strip().capitalize()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "status": (result.status or "").strip().upper(),
        "status_guidance": SCAN_STATUS_GUIDANCE.get(
            (result.status or "").strip().upper(), ""
        ),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "evidence_records": len(result.footprint_data or []),
        "modules": modules,
    }


def filter_footprint(footprint_data, query="", module="All",
                     subcategories=None, exclude_subcategories=None):
    """Return footprint records matching search, module, and subcategory filters.

    Matching is case-insensitive over value, source, and subcategory.
    subcategories limits to the given subcategory names; exclude_subcategories
    removes them instead (for "everything else" groups). The underlying data
    is never modified or truncated by the caller rule; filtering only affects
    what is rendered.
    """
    query = (query or "").strip().lower()
    records = list(footprint_data or [])
    if module and module != "All":
        records = [fd for fd in records if getattr(fd, "category", "") == module]
    if subcategories is not None:
        wanted = set(subcategories)
        records = [fd for fd in records if getattr(fd, "subcategory", "") in wanted]
    if exclude_subcategories:
        excluded = set(exclude_subcategories)
        records = [fd for fd in records if getattr(fd, "subcategory", "") not in excluded]
    if query:
        records = [
            fd for fd in records
            if query in str(getattr(fd, "value", "")).lower()
            or query in str(getattr(fd, "source", "")).lower()
            or query in str(getattr(fd, "subcategory", "")).lower()
        ]
    return records


# Evidence groups larger than this show a collapse control in evidence views.
EVIDENCE_GROUP_COLLAPSE_THRESHOLD = 10

# Per-tab evidence group filter options mapping to
# (subcategories, exclude_subcategories) for filter_footprint().
# None selects the unfiltered record set for that dimension.
_VIEW_GROUP_FILTERS = {
    "sys": {
        "All groups": (None, None),
        "Installed Applications": ({"Installed Applications"}, None),
        "Running Processes": ({"Running Processes"}, None),
        "Startup Applications": ({"Startup Applications"}, None),
        "General info": (None, {"Installed Applications", "Running Processes",
                                "Startup Applications"}),
    },
    "browser": {
        "All groups": (None, None),
        "Detected Browsers": ({"Detected Browser"}, None),
        "Extensions": ({"Extension"}, None),
        "Coverage notes": (None, {"Detected Browser", "Extension"}),
    },
    "file": {
        "All groups": (None, None),
        "File details": ({"File Information", "File Path", "File Timestamps"}, None),
        "Sensitive metadata": ({"Potentially Sensitive"}, None),
        "Extracted metadata": ({"Embedded Metadata"}, None),
    },
}

# Description lines above this count are previewed with a Show-all link in
# coverage blocks.
COVERAGE_DESCRIPTION_PREVIEW_LIMIT = 8


def filter_note_html(matched, total):
    """Shared "N of M records" match note for filtered evidence views."""
    return (
        f'<div style="font-size: 12px; color: {R('muted')}; margin-bottom: 8px;">'
        f'Filter matched <b>{matched}</b> of <b>{total}</b> records.</div>'
    )


def parse_evidence_record(subcategory, value):
    """Split a pre-joined evidence value into (headline, visible, hidden).

    Uses the stable " | " segment conventions produced by the scan
    controller (extension, startup, process, browser records). Visible lines
    always render; hidden lines render behind a Details control and only for
    extension records. Anything unrecognized falls back to the raw value as
    the headline, so no information is ever lost or restructured blindly.
    """
    text = str(value)
    segments = [s.strip() for s in text.split(" | ")]

    def _after(prefix, segment):
        return segment[len(prefix):].strip() if segment.startswith(prefix) else None

    if subcategory == "Extension" and len(segments) > 1:
        name = segments[0]
        fields = {}
        rest = []
        for seg in segments[1:]:
            matched = False
            for prefix in ("ID:", "Browser:", "Profile:"):
                val = _after(prefix, seg)
                if val is not None:
                    fields[prefix[:-1]] = val
                    matched = True
                    break
            if not matched:
                rest.append(seg)
        context = " / ".join(p for p in (
            fields.get("Browser"), fields.get("Profile")) if p)
        headline = f"{name} · {context}" if context else name
        description = " ".join(rest)
        short = description if len(description) <= 140 else description[:137] + "…"
        hidden = []
        if fields.get("ID"):
            hidden.append(f"ID: {fields['ID']}")
        if description:
            hidden.append(description)
        return headline, ([short] if short else []), hidden

    if subcategory == "Startup Applications" and segments and segments[0].startswith("Name:"):
        headline = segments[0][len("Name:"):].strip() or text
        return headline, segments[1:], []

    if subcategory == "Running Processes" and segments:
        return segments[0] or text, segments[1:], []

    if subcategory == "Detected Browser" and len(segments) > 1:
        return segments[0], segments[1:], []

    return text, [], []


def format_evidence_record_html(subcategory, value, source, view_key=None,
                                  record_key=None, expanded=False, marker="•",
                                  headline_color=None):
    """Render one evidence record with a headline-first layout.

    The headline carries the most important field, remaining fields follow
    as muted detail lines, and the source tag stays visible. Extension
    technical details render behind a Details control when a view context
    is supplied; otherwise everything renders inline (legacy behavior).
    Marker and headline color preserve established per-section accents
    (e.g. sensitive metadata warnings).
    """
    headline, visible, hidden = parse_evidence_record(subcategory, value)
    source_html = (
        f' <span style="color: {R('faint')}; font-size: 11px;">[Source: {html.escape(str(source))}]</span>'
        if source else ""
    )
    if " — " in headline and not headline_color:
        name_part, rest_part = headline.split(" — ", 1)
        headline_open = (
            f'<b>{html.escape(name_part)}</b>'
            f'<span style="color: {R('muted')};"> — {html.escape(rest_part)}</span>'
        )
    elif headline_color:
        headline_open = (
            f'<span style="color: {headline_color};"><b>{html.escape(headline)}</b></span>'
        )
    else:
        headline_open = f'<b>{html.escape(headline)}</b>'

    def _detail_div(text, color):
        # Path-like values and identifiers render monospace for scannability;
        # prose stays in proportional type.
        mono = "/" in text or "\\" in text or text.startswith("ID:")
        family = "font-family: monospace; " if mono else ""
        return (
            f'<div style="font-size: 12px; color: {color}; margin: 0 0 3px 14px; '
            f'{family}word-break: break-all;">{html.escape(text)}</div>'
        )

    lines = [
        f'<div style="font-size: 12px; margin-bottom: 2px; word-break: break-all;">'
        f'<span style="color: {R('link')};">{html.escape(marker)}</span> {headline_open}{source_html}</div>'
    ]
    for detail in visible:
        lines.append(_detail_div(detail, f"{R('muted')}"))
    if hidden:
        if expanded:
            for detail in hidden:
                lines.append(_detail_div(detail, f"{R('text')}"))
            if view_key is not None and record_key is not None:
                lines.append(
                    f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                    f'<a href="#evd-{view_key}-{record_key}-hide" style="color: {R('link')};">'
                    f'Hide details</a></div>'
                )
        elif view_key is not None and record_key is not None:
            lines.append(
                f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                f'<a href="#evd-{view_key}-{record_key}-show" style="color: {R('link')};">'
                f'Details</a></div>'
            )
        else:
            for detail in hidden:
                lines.append(
                    f'<div style="font-size: 11px; color: {R('muted')}; margin: 0 0 2px 14px; '
                    f'word-break: break-all;">{html.escape(detail)}</div>'
                )
    return "\n".join(lines)


def format_evidence_group_open(title_html, count, view_key=None, group_key=None,
                               collapsed=False, collapsible=True):
    """Render an evidence group header, optionally with collapse controls.

    Returns (header_html, show_body). Collapsed groups hide their records
    behind an expand link; the records themselves are never discarded.
    """
    if (view_key is not None and group_key is not None
            and collapsible and count > EVIDENCE_GROUP_COLLAPSE_THRESHOLD):
        if collapsed:
            return (
                f'{title_html} '
                f'<a href="#evd-{view_key}-g-{group_key}-show" style="color: {R('link')}; '
                f'font-size: 11px; font-weight: normal;">Expand ({count} records hidden)</a>',
                False,
            )
        return (
            f'{title_html} '
            f'<a href="#evd-{view_key}-g-{group_key}-hide" style="color: {R('link')}; '
            f'font-size: 11px; font-weight: normal;">Collapse</a>',
            True,
        )
    return title_html, True


def format_finding_evidence_html(evidence, preview_limit=FINDING_EVIDENCE_PREVIEW_LIMIT,
                                   expanded=False, card_index=None):
    """Render finding evidence as readable bullet lines with a preview cap.

    When collapsed, at most preview_limit entries are shown with a "+N more"
    note and a Show-all link (card_index identifies the card to expand).
    When expanded, all entries render with a Show-less link. Full records
    always remain available in the Collected Evidence view.
    """
    items = collect_finding_evidence_items(evidence)
    if not items:
        return f'<div style="font-size: 11px; color: {R("faint_meta")}; font-style: italic;">No evidence recorded.</div>'

    if expanded or len(items) <= preview_limit:
        shown = items
    else:
        shown = items[:preview_limit]
    lines = []
    for item in shown:
        lines.append(
            f'<div style="font-size: 11px; margin-bottom: 2px; word-break: break-all;">'
            f'<span style="color: {R('link')};">•</span> {html.escape(item)}</div>'
        )
    remaining = len(items) - len(shown)
    if card_index is not None and (remaining > 0 or expanded):
        if expanded:
            lines.append(
                f'<div style="font-size: 11px; margin-top: 4px;">'
                f'<a href="#ev-{card_index}-hide" style="color: {R('link')};">Show less</a>'
                f'<span style="color: {R('faint_meta')};"> · full list also in Collected Evidence.</span></div>'
            )
        else:
            lines.append(
                f'<div style="font-size: 11px; color: {R('faint_meta')}; font-style: italic; margin-top: 4px;">'
                f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
                f'<a href="#ev-{card_index}-show" style="color: {R('link')};">Show all</a> · '
                f'see Collected Evidence for the complete records.</div>'
            )
    elif remaining > 0:
        lines.append(
            f'<div style="font-size: 11px; color: {R('faint_meta')}; font-style: italic; margin-top: 4px;">'
            f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
            f'see Collected Evidence for the complete records.</div>'
        )
    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Footprint Analyzer")
        self.resize(1120, 740)

        self.worker = None
        self.selected_file_path = None
        self.full_scan_file_path = None
        # Display-only render state: last result per findings view plus the
        # set of expanded evidence-card indices per view. Never affects scan
        # semantics; cleared whenever a new result arrives for a view.
        self._last_results = {}

        # Widgets whose stylesheet is built from theme tokens, kept as
        # (widget, template) pairs so one pass can restyle all of them when
        # the theme changes. No panel is left holding the old theme's colors.
        self._themed_widgets = []
        self._expanded_cards = {}
        self._evidence_filter_timer = None
        self._pending_evidence_view = None
        # Per-view evidence-explorer state (collapsed groups and expanded
        # records), reset on new results or filter changes. Presentation only.
        self._collapsed_evidence = {}
        self._expanded_evidence_records = {}
        # Dashboard state (presentation only): bounded in-session scan
        # history plus the latest result summary. Never affects scanning.
        self._scan_history = []
        self._dashboard_summary = None

        # Unified assessment state for the most recent scan: the one
        # RiskSummary every page reads, the remediation plan built from it,
        # and the board that pairs that plan with the user's own marks.
        self.latest_risk = None
        self.latest_result = None
        self.latest_plan = None
        self.latest_board = None

        # Local persistence. Both stores keep everything on this device and
        # are created lazily/tolerantly: a storage problem must never stop the
        # application from scanning.
        self._history_error = ""
        try:
            self.history_store = ScanHistoryStore()
        except HistoryStoreError as error:
            self.history_store = None
            self._history_error = str(error)
        try:
            self.action_store = ActionStateStore()
        except HistoryStoreError as error:
            self.action_store = None
            self._history_error = self._history_error or str(error)

        # Persisted user preferences. Read before any widget is built so the
        # first paint already uses the saved theme.
        self.app_settings = QSettings("DigitalFootprintAnalyzer", "Preferences")
        self.current_theme = str(
            self.app_settings.value("theme_mode", "dark")).strip().lower()
        if self.current_theme not in ("system", "light", "dark"):
            self.current_theme = "dark"
        self.high_contrast = self.app_settings.value(
            "high_contrast_selection", True, type=bool)
        self.font_scale = int(self.app_settings.value("font_scale", 13))
        self.evidence_preview_limit = int(self.app_settings.value(
            "evidence_preview_limit", FINDING_EVIDENCE_PREVIEW_LIMIT))
        self.process_collector_mode = str(self.app_settings.value(
            "process_collector_mode",
            DEFAULT_PROCESS_COLLECTOR_MODE))
        if self.process_collector_mode not in PROCESS_COLLECTOR_MODES:
            self.process_collector_mode = DEFAULT_PROCESS_COLLECTOR_MODE
        self.network_timeout = int(self.app_settings.value("network_timeout", 10))
        # The theme module is process-global, so tell it which map to use
        # before any widget resolves R() during construction.
        theme.set_dark_theme(self.is_dark_mode)

        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(12)

        # Sidebar navigation with product branding header and footer.
        sidebar_container = QWidget()
        sidebar_container.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar_container)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(6)

        logo_row = QHBoxLayout()
        logo_row.setSpacing(10)
        self.sidebar_emblem = QLabel()
        self.sidebar_emblem.setPixmap(pixmap("fingerprint", 36))
        logo_row.addWidget(self.sidebar_emblem)
        self.sidebar_logo = QLabel("<b>Digital Footprint<br><span style='color: #2dd4bf;'>Analyzer</span></b>")
        self.sidebar_logo.setWordWrap(True)
        logo_row.addWidget(self.sidebar_logo, stretch=1)
        logo_widget = QWidget()
        logo_widget.setLayout(logo_row)
        logo_widget.setStyleSheet("padding: 12px 10px 8px 10px;")
        sidebar_layout.addWidget(logo_widget)

        self.sidebar = QListWidget()
        self.sidebar.setIconSize(QSize(20, 20))
        for label, icon_name in (
            ("Home", "home"),
            ("My Footprint", "search"),
            ("Public Lookup", "globe"),
            ("Settings", "gear"),
            ("Assessment", "target"),
            ("Evidence", "layers"),
            ("Actions", "shield_check"),
            ("History", "clock"),
        ):
            item = QListWidgetItem(icon(icon_name), label)
            self.sidebar.addItem(item)
        self.sidebar.currentRowChanged.connect(self.change_page)
        sidebar_layout.addWidget(self.sidebar, stretch=1)

        # Bottom footer tagline card (matches reference UI)
        footer_frame = QFrame()
        footer_frame.setObjectName("sidebar_footer")
        footer_frame.setStyleSheet(
            f"QFrame#sidebar_footer {{ background-color: {R('panel_bg')}; "
            f"border: 1px solid {R('panel_border')}; border-radius: 8px; "
            "margin: 8px 6px; padding: 6px; }"
        )
        footer_layout = QHBoxLayout(footer_frame)
        footer_layout.setContentsMargins(6, 6, 6, 6)
        footer_layout.setSpacing(8)
        footer_icon = QLabel()
        footer_icon.setPixmap(pixmap("shield_check", 22))
        footer_layout.addWidget(footer_icon)
        self.sidebar_tagline = QLabel("Your privacy.<br><b>Your control.</b>")
        self.sidebar_tagline.setWordWrap(True)
        self.register_themed_widget(
            self.sidebar_tagline,
            "color: {muted}; font-size: 11px;")
        footer_layout.addWidget(self.sidebar_tagline, stretch=1)
        sidebar_layout.addWidget(footer_frame)
        main_layout.addWidget(sidebar_container)

        # Stacked widget for pages
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages)

        # Initialize pages
        self.init_home_page()
        self.init_my_footprint_page()
        self.init_public_lookup_page()
        self.init_settings_page()
        self.init_expanded_pages()

        self.sidebar.setCurrentRow(0)  # Default to the Home dashboard

        # Repaint only this window's own styled widgets. The application
        # palette and stylesheet are applied by main.py before the first
        # window is built, so restyling the whole app here would be wasted
        # work on every construction. Runtime switches go through
        # apply_theme(), which does restyle everything.
        self._refresh_home_theme()

    def init_home_page(self):
        page = QScrollArea()
        page.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(14)

        # Hero banner row with high-tech laptop vector graphic and reference typography
        hero_row = QHBoxLayout()
        hero_row.setSpacing(16)
        hero = QLabel(
            f"<div style='font-size: 13px; color: {R('muted')}; margin-bottom: 2px;'>Welcome to</div>"
            f"<div style='font-size: 26px; font-weight: bold;'>Digital Footprint "
            f"<span style='color: {R('accent')};'>Analyzer</span></div>"
            f"<div style='font-size: 12px; color: {R('muted')}; margin-top: 4px;'>Understand your digital "
            "footprint. Keep your data in your hands.</div>"
        )
        hero.setWordWrap(True)
        hero_row.addWidget(hero, stretch=1)

        self.hero_emblem = QLabel()
        self.hero_emblem.setAlignment(Qt.AlignCenter)
        self.hero_emblem.setFixedSize(240, 130)
        self.hero_emblem.setPixmap(pixmap("laptop_hero", (240, 130)))
        self.register_themed_widget(
            self.hero_emblem,
            "background: transparent; border: none; padding: 0;")
        hero_row.addWidget(self.hero_emblem)

        self.hero_tagline = QLabel(
            "<div style='letter-spacing: 1px; line-height: 1.5; font-size: 10px; font-weight: bold;'>"
            "ANALYZE<br>DISCOVER<br>STAY INFORMED<br>STAY IN CONTROL"
            "<div style='margin-top: 6px; width: 34px; height: 2px; background: #2dd4bf;'></div></div>"
        )
        self.register_themed_widget(self.hero_tagline, "color: {muted};")
        hero_row.addWidget(self.hero_tagline)
        layout.addLayout(hero_row)

        # 4 Quick Scan cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)
        self.home_cards = {}
        self.home_card_frames = {}
        for key, title, description, icon_name in (
            ("system", "System Footprint",
             "Discover installed applications, running processes, startup items and other system information.",
             "monitor"),
            ("browser", "Browser Footprint",
             "Analyze browser data, extensions, profiles and stored information.",
             "globe"),
            ("file", "File Metadata",
             "Inspect metadata from selected files.",
             "document"),
            ("full", "Full Scan",
             "Run system and browser scans together for a complete overview.",
             "target"),
        ):
            card, action_btn = self._make_scan_card(title, description, icon_name)
            cards_row.addWidget(card, stretch=1)
            self.home_cards[key] = action_btn
            self.home_card_frames[key] = card
        layout.addLayout(cards_row)
        self.home_cards["system"].clicked.connect(self._start_dashboard_system)
        self.home_cards["browser"].clicked.connect(self._start_dashboard_browser)
        self.home_cards["file"].clicked.connect(self._start_dashboard_file)
        self.home_cards["full"].clicked.connect(self._start_dashboard_full)

        # Exposure assessment strip: the same RiskSummary the Assessment page,
        # the reports, and history use. It shows nothing until a scan exists.
        risk_card = QFrame()
        risk_card.setObjectName("home_risk_card")
        self.register_themed_widget(
            risk_card,
            "background-color: {panel_bg_alt}; border: 1px solid "
            "{panel_border}; border-radius: 10px;")
        risk_box = QHBoxLayout(risk_card)
        risk_box.setContentsMargins(16, 12, 16, 12)
        risk_box.setSpacing(16)

        risk_text = QVBoxLayout()
        risk_text.setSpacing(2)
        risk_heading = QLabel("<b>Exposure assessment</b>")
        risk_heading.setStyleSheet("font-size: 13px;")
        risk_text.addWidget(risk_heading)
        self.home_risk_label = QLabel()
        self.home_risk_label.setWordWrap(True)
        risk_text.addWidget(self.home_risk_label)
        self.home_actions_label = QLabel()
        self.home_actions_label.setWordWrap(True)
        risk_text.addWidget(self.home_actions_label)
        risk_box.addLayout(risk_text, stretch=1)

        risk_buttons = QVBoxLayout()
        risk_buttons.setSpacing(6)
        self.home_assessment_btn = QPushButton("Open assessment")
        self.home_assessment_btn.clicked.connect(self._open_assessment)
        risk_buttons.addWidget(self.home_assessment_btn)
        self.home_actions_btn = QPushButton("Open action centre")
        self.home_actions_btn.clicked.connect(self._open_actions_page)
        risk_buttons.addWidget(self.home_actions_btn)
        self.home_history_btn = QPushButton("Scan history")
        self.home_history_btn.clicked.connect(self._open_history_page)
        risk_buttons.addWidget(self.home_history_btn)
        risk_box.addLayout(risk_buttons)
        layout.addWidget(risk_card)

        # Middle row: Footprint Overview (left) and Privacy Checklist (right)
        middle_row = QHBoxLayout()
        middle_row.setSpacing(12)

        # Left Column: Footprint Overview Container Card
        overview_card = QFrame()
        overview_card.setObjectName("overview_card")
        overview_card.setStyleSheet(
            f"QFrame#overview_card {{ background-color: {R('panel_bg_alt')}; border: 1px solid {R('panel_border')}; "
            "border-radius: 10px; }"
        )
        overview_box = QVBoxLayout(overview_card)
        overview_box.setContentsMargins(14, 14, 14, 14)
        overview_box.setSpacing(6)

        overview_header = QHBoxLayout()
        overview_icon = QLabel()
        overview_icon.setPixmap(pixmap("chart", 20))
        overview_header.addWidget(overview_icon)
        overview_title = QLabel("<b>Footprint Overview</b>")
        overview_title.setStyleSheet("font-size: 14px; color: #ffffff;")
        overview_header.addWidget(overview_title)
        overview_header.addStretch()

        self.overview_scan_combo = QComboBox()
        self.overview_scan_combo.addItem("Last Scan")
        self.overview_scan_combo.setMinimumWidth(120)
        self.overview_scan_combo.currentIndexChanged.connect(self._on_overview_scan_changed)
        overview_header.addWidget(self.overview_scan_combo)
        overview_box.addLayout(overview_header)
        overview_sub = QLabel("A summary of the last scan results. Run a scan to analyze your digital footprint.")
        self.register_themed_widget(
            overview_sub, "color: {muted}; font-size: 11px;")
        overview_sub.setWordWrap(True)
        overview_box.addWidget(overview_sub)

        self.dashboard_overview = QTextBrowser()
        self.dashboard_overview.setOpenLinks(False)
        self.dashboard_overview.setReadOnly(True)
        self.dashboard_overview.setMinimumHeight(260)
        self.dashboard_overview.setStyleSheet("border: none; background: transparent;")
        overview_box.addWidget(self.dashboard_overview, stretch=1)
        middle_row.addWidget(overview_card, stretch=3)

        # Right Column: Privacy Checklist Container Card
        checklist_card = QFrame()
        checklist_card.setObjectName("checklist_card")
        checklist_card.setStyleSheet(
            f"QFrame#checklist_card {{ background-color: {R('panel_bg_alt')}; border: 1px solid {R('panel_border')}; "
            "border-radius: 10px; }"
        )
        checklist_box = QVBoxLayout(checklist_card)
        checklist_box.setContentsMargins(14, 14, 14, 14)
        checklist_box.setSpacing(8)

        checklist_header = QHBoxLayout()
        checklist_icon = QLabel()
        checklist_icon.setPixmap(pixmap("shield", 20))
        checklist_header.addWidget(checklist_icon)
        checklist_title = QLabel("<b>Privacy Checklist</b>")
        checklist_title.setStyleSheet("font-size: 14px; color: #ffffff;")
        checklist_header.addWidget(checklist_title)
        checklist_header.addStretch()
        checklist_box.addLayout(checklist_header)

        checklist_sub = QLabel("Simple steps to improve your privacy and reduce your exposure.")
        self.register_themed_widget(
            checklist_sub, "color: {muted}; font-size: 11px;")
        checklist_sub.setWordWrap(True)
        checklist_box.addWidget(checklist_sub)

        for title, sub, tab_index, row_icon in (
            ("Review startup applications", "Disable applications you no longer need.", 0, "shield_check"),
            ("Check browser extensions", "Remove unnecessary or unfamiliar extensions.", 1, "window"),
            ("Be mindful when sharing files", "Metadata can reveal more information than you might expect.", 2, "document"),
        ):
            row = QFrame()
            row_id = f"checklist_row_{tab_index}"
            row.setObjectName(row_id)
            row.setFrameShape(QFrame.NoFrame)
            self.register_themed_widget(
                row,
                "QFrame#" + row_id +
                " {{ background-color: {panel_bg}; "
                "border: 1px solid {panel_border}; border-radius: 6px; }}")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(10, 6, 10, 6)
            row_layout.setSpacing(10)
            row_icon_label = QLabel()
            row_icon_label.setPixmap(pixmap(row_icon, 22))
            row_layout.addWidget(row_icon_label)
            text = QLabel(f"<b>{html.escape(title)}</b><br>"
                          f"<span style='color: {R('muted')}; font-size: 11px;'>{html.escape(sub)}</span>")
            text.setWordWrap(True)
            row_layout.addWidget(text, stretch=1)
            go_btn = QPushButton("›")
            go_btn.setFixedSize(30, 30)
            self.register_themed_widget(
                go_btn,
                "QPushButton {{ border: 1px solid {accent}; border-radius: 15px; "
                "font-size: 16px; font-weight: bold; color: {accent}; "
                "background-color: {accent_soft}; padding: 0px; text-align: center; }} "
                "QPushButton:hover {{ background-color: {accent}; color: {on_accent}; }}")
            go_btn.clicked.connect(
                lambda _checked=False, tab=tab_index: self._goto_my_footprint_tab(tab)
            )
            row_layout.addWidget(go_btn)
            checklist_box.addWidget(row)

        tip_frame = QFrame()
        tip_frame.setObjectName("tip_frame")
        tip_frame.setStyleSheet(
            f"QFrame#tip_frame {{ background-color: {R('panel_bg')}; border: 1px solid {R('panel_border')}; "
            "border-radius: 6px; padding: 4px; }"
        )
        tip_layout = QHBoxLayout(tip_frame)
        tip_layout.setContentsMargins(10, 8, 10, 8)
        tip_layout.setSpacing(10)
        tip_icon = QLabel()
        tip_icon.setPixmap(pixmap("lightbulb", 22, "#fbbf24"))
        tip_layout.addWidget(tip_icon)
        tip = QLabel("<b>Tip:</b> Run a Full Scan periodically to get a complete "
                     "overview of your digital footprint.")
        tip.setWordWrap(True)
        self.register_themed_widget(
            tip, "color: {muted}; font-size: 11px;")
        tip_layout.addWidget(tip, stretch=1)
        checklist_box.addWidget(tip_frame)
        checklist_box.addStretch()
        middle_row.addWidget(checklist_card, stretch=2)
        layout.addLayout(middle_row)

        # Recent Scans Section (Bottom)
        recent_card = QFrame()
        recent_card.setObjectName("recent_card")
        recent_card.setStyleSheet(
            f"QFrame#recent_card {{ background-color: {R('panel_bg_alt')}; border: 1px solid {R('panel_border')}; "
            "border-radius: 10px; }"
        )
        recent_box = QVBoxLayout(recent_card)
        recent_box.setContentsMargins(14, 14, 14, 14)
        recent_box.setSpacing(6)

        recent_row = QHBoxLayout()
        recent_icon = QLabel()
        recent_icon.setPixmap(pixmap("clock", 18))
        recent_row.addWidget(recent_icon)
        recent_title = QLabel("<b>Recent Scans</b>")
        recent_title.setStyleSheet("font-size: 14px; color: #ffffff;")
        recent_row.addWidget(recent_title)
        recent_row.addStretch()

        self.view_all_scans_btn = QPushButton("View All Scans ›")
        self.view_all_scans_btn.setStyleSheet(
            "QPushButton { border: 1px solid #1d334d; border-radius: 6px; padding: 5px 12px; font-size: 12px; } "
            "QPushButton:hover { border-color: #2dd4bf; color: #2dd4bf; }"
        )
        self.view_all_scans_btn.clicked.connect(self._open_history_dialog)
        recent_row.addWidget(self.view_all_scans_btn)
        recent_box.addLayout(recent_row)

        recent_sub = QLabel("Your latest scans are shown below.")
        recent_sub.setStyleSheet(f"color: {R('muted')}; font-size: 11px; margin-bottom: 4px;")
        recent_box.addWidget(recent_sub)

        self.recent_scans_table = QTableWidget(0, 6)
        self.recent_scans_table.setHorizontalHeaderLabels(
            ["Date & Time", "Scan Type", "Modules", "Findings", "Evidence Items", "Status"]
        )
        self.recent_scans_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_scans_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent_scans_table.setSelectionMode(QTableWidget.NoSelection)
        self.recent_scans_table.setMaximumHeight(180)
        recent_box.addWidget(self.recent_scans_table)
        layout.addWidget(recent_card)

        page.setWidget(content)
        self.pages.addWidget(page)
        self.dashboard_overview.setHtml(self._format_dashboard_overview_html())

    def _make_scan_card(self, title, description, icon_name="target"):
        card = QFrame()
        card.setObjectName("scan_card")
        card.setFrameShape(QFrame.NoFrame)
        self.register_themed_widget(
            card,
            "QFrame#scan_card {{ background-color: {panel_bg_alt}; "
            "border: 1px solid {panel_border}; border-radius: 10px; padding: 6px; }} "
            "QFrame#scan_card:hover {{ border: 1px solid {accent}; "
            "background-color: {panel_hover}; }}")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setSpacing(6)
        icon_label = QLabel()
        icon_label.setPixmap(pixmap(icon_name, 28))
        card_layout.addWidget(icon_label)
        title_label = QLabel(f"<b>{html.escape(title)}</b>")
        title_label.setWordWrap(True)
        title_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #ffffff;")
        card_layout.addWidget(title_label)
        desc_label = QLabel(html.escape(description))
        desc_label.setWordWrap(True)
        self.register_themed_widget(
            desc_label, "color: {muted}; font-size: 11px;")
        desc_label.setAlignment(Qt.AlignTop)
        card_layout.addWidget(desc_label, stretch=1)
        action_btn = QPushButton("›")
        action_btn.setFixedSize(34, 34)
        self.register_themed_widget(
            action_btn,
            "QPushButton {{ border: 1px solid {accent}; border-radius: 17px; "
            "font-size: 17px; font-weight: bold; color: {accent}; "
            "background-color: {accent_soft}; padding: 0px; text-align: center; }} "
            "QPushButton:hover {{ background-color: {accent}; color: {on_accent}; }}")
        card_layout.addWidget(action_btn, alignment=Qt.AlignRight)
        return card, action_btn

    def _goto_my_footprint_tab(self, index):
        self.sidebar.setCurrentRow(1)
        self.my_footprint_tabs.setCurrentIndex(index)

    def _start_dashboard_system(self):
        self._goto_my_footprint_tab(0)
        self.start_system_scan()

    def _start_dashboard_browser(self):
        self._goto_my_footprint_tab(1)
        self.start_browser_scan()

    def _start_dashboard_file(self):
        self._goto_my_footprint_tab(2)

    def _start_dashboard_full(self):
        self._goto_my_footprint_tab(3)
        self.start_full_scan()

    def _record_dashboard_entry(self, result):
        """Build a session history entry from a finished ScanResult.

        Presentation-only: findings/evidence counts and module labels are
        read straight from the result. History is bounded in memory and
        never persisted.
        """
        scan_type = result.scan_type or "Unknown"
        summary = self._dashboard_summary_for(result)
        if scan_type == "Full Scan":
            attempted = [m for m in summary["modules"] if m["state"] != "skipped"]
            done = [m for m in attempted if m["state"] == "completed"]
            modules_label = " + ".join(m["name"] for m in attempted) or scan_type
            modules_count = f"{len(done)} / {len(attempted)}" if attempted else "0 / 0"
        else:
            modules_label = scan_type
            modules_count = "1 / 1"
        return {
            "time": datetime.now().strftime("%d %b %Y, %I:%M %p"),
            "scan_type": scan_type,
            "modules": modules_label,
            "modules_count": modules_count,
            "findings": len(result.findings or []),
            "evidence": len(result.footprint_data or []),
            "status": (result.status or "").strip().upper(),
            "severity_counts": dict(summary["severity_counts"]),
            "module_rows": [dict(m) for m in summary["modules"]],
        }

    def _dashboard_summary_for(self, result):
        """Build the overview model for any finished scan.

        Full Scan reuses the shared display adapter; individual scans get a
        single-module row derived from their own status. Read-only.
        """
        if result.scan_type == "Full Scan":
            return summarize_full_scan(result)
        status = (result.status or "").strip().upper()
        # One module, so its coverage row is the whole picture. The shared
        # derivation decides the state, including explicit unavailability.
        module_row = scan_coverage.derive_scan_coverage(result)[0]
        state = module_row["state"]
        note = module_row["note"]
        severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in result.findings or []:
            sev = (f.severity or "Info").strip().capitalize()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "status": status,
            "status_guidance": SCAN_STATUS_GUIDANCE.get(status, ""),
            "total_findings": len(result.findings or []),
            "severity_counts": severity_counts,
            "evidence_records": len(result.footprint_data or []),
            "modules": [{"name": result.scan_type or "Unknown",
                         "state": state, "note": note}],
        }

    def _refresh_dashboard(self, result):
        """Fold a finished scan into the dashboard history and re-render."""
        self._dashboard_summary = self._dashboard_summary_for(result)
        self._scan_history.insert(0, self._record_dashboard_entry(result))
        del self._scan_history[20:]
        self.overview_scan_combo.blockSignals(True)
        self.overview_scan_combo.clear()
        self.overview_scan_combo.addItem("Last Scan")
        for entry in self._scan_history:
            self.overview_scan_combo.addItem(
                f'{entry["time"]} — {entry["scan_type"]}')
        self.overview_scan_combo.blockSignals(False)
        self.dashboard_overview.setHtml(self._format_dashboard_overview_html())
        self._populate_history_table(self.recent_scans_table, self._scan_history[:5])

    def _summary_from_entry(self, entry):
        """Rebuild an overview model from a stored history entry."""
        return {
            "status": entry["status"],
            "status_guidance": SCAN_STATUS_GUIDANCE.get(entry["status"], ""),
            "total_findings": entry["findings"],
            "severity_counts": dict(entry["severity_counts"]),
            "evidence_records": entry["evidence"],
            "modules": [dict(m) for m in entry["module_rows"]],
        }

    def _on_overview_scan_changed(self, index):
        # Index 0 ("Last Scan") shows the latest summary; any other index
        # shows that session entry's stored summary. Read-only throughout.
        if index <= 0 or not self._scan_history:
            summary = self._dashboard_summary
        elif index - 1 < len(self._scan_history):
            summary = self._summary_from_entry(self._scan_history[index - 1])
        else:
            return
        if summary is None:
            return
        self.dashboard_overview.setHtml(
            self._format_dashboard_overview_html(summary))

    def _format_dashboard_overview_html(self, summary=None):
        """Render the overview panel from a dashboard summary model."""
        if summary is None:
            summary = self._dashboard_summary
        if summary is None:
            return (
                '<div style="font-family: sans-serif; padding: 4px; font-size: 12px; '
                f'color: {R("muted")};">Run a scan to analyze your digital footprint. '
                'Results from System, Browser, File, Full Scan, and Public Lookup '
                'scans appear here.</div>'
            )
        counts = summary["severity_counts"]
        peak = max(counts.values()) if counts else 0
        bar_colors = {
            "Critical": f"{R('sev_critical')}", "High": f"{R('sev_medium')}", "Medium": f"{R('chart_medium')}",
            "Low": f"{R('sev_low')}", "Info": f"{R('link')}",
        }
        bars = []
        for sev in SEVERITY_ORDER:
            count = counts.get(sev, 0)
            height = 6 if not peak else 6 + round(54 * count / peak)
            bars.append(
                f'<td align="center" valign="bottom" style="padding: 0 6px;">'
                f'<div style="font-size: 11px; font-weight: bold; color: {R('text')};">{count}</div>'
                f'<div style="width: 28px; height: {height}px; '
                f'background-color: {bar_colors.get(sev, f"{R('link')}")}; '
                f'border-radius: 3px 3px 0 0;">&nbsp;</div>'
                f'<div style="font-size: 11px; color: {R('muted')};">{html.escape(sev)}</div>'
                f'</td>'
            )
        state_marks = {"completed": (f"{R('ok_text')}", "✓"), "limited": (f"{R('warn_text')}", "⚠"),
                       "failed": (f"{R('err_text')}", "✕"), "skipped": (f"{R('muted')}", "⊘"),
                       "unavailable": (f"{R('warn_text')}", "⊘"),
                       "unknown": (f"{R('faint_alt')}", "?")}
        module_lines = []
        for mod in summary.get("modules", []):
            color, mark = state_marks.get(mod.get("state", "unknown"), (f"{R('faint_alt')}", "?"))
            module_lines.append(
                f'<div style="font-size: 12px; margin-bottom: 2px; color: {R('text_alt')};">'
                f'<span style="color: {color}; font-weight: bold;">{mark}</span> '
                f'<b>{html.escape(mod.get("name", "?"))}:</b> '
                f'{html.escape(mod.get("note", ""))}</div>'
            )
        modules_html = f"""
          <div style="font-weight: bold; font-size: 12px; margin: 8px 0 4px;">Modules:</div>
          {"".join(module_lines)}
        """ if module_lines else ""
        status = summary["status"]
        status_color = {"COMPLETED": f"{R('ok_text')}", "PARTIAL": f"{R('warn_text')}",
                        "ERROR": f"{R('err_text')}"}.get(status, f"{R('muted')}")
        critical = counts.get("Critical", 0)
        status_note = (f"{critical} critical need attention" if critical
                       else "No critical issues")
        modules = summary.get("modules", [])
        if len(modules) > 1:
            attempted = [m for m in modules if m["state"] != "skipped"]
            done = [m for m in attempted if m["state"] == "completed"]
            modules_count = f"{len(done)} / {len(attempted)}" if attempted else "0 / 0"
            modules_label = " + ".join(m["name"] for m in attempted) or "—"
        else:
            modules_count = "1 / 1"
            modules_label = modules[0]["name"] if modules else "—"
        concern_count = counts.get("Critical", 0) + counts.get("High", 0)
        obs_count = counts.get("Medium", 0) + counts.get("Low", 0) + counts.get("Info", 0)
        findings_note = f"{concern_count} concerns | {obs_count} observations"
        wave_svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 380 30" width="100%" height="24" style="margin-bottom: -10px;">'
            f'<path d="M 0,20 Q 60,5 120,20 T 240,15 T 380,24" fill="none" stroke="{R("link")}" stroke-width="1.6" stroke-opacity="0.45"/>'
            f'<path d="M 0,25 Q 70,12 140,24 T 280,12 T 380,20" fill="none" stroke="{R("link")}" stroke-width="1.0" stroke-opacity="0.25"/>'
            f'</svg>'
        )
        return f"""
        <div style="font-family: sans-serif; padding: 2px;">
          <table width="100%" cellpadding="6" cellspacing="5" style="font-size: 12px; color: {R('text_alt')};">
            <tr>
              <td style="border: 1px solid {R('panel_border')}; border-radius: 6px; background-color: {R('panel_bg')};">
                <span style="font-size: 11px; color: {R('muted')};">Total Findings</span><br>
                <span style="font-size: 17px; font-weight: bold; color: {R('text')};">{summary["total_findings"]}</span><br>
                <span style="font-size: 10px; color: {R('muted')};">{findings_note}</span></td>
              <td style="border: 1px solid {R('panel_border')}; border-radius: 6px; background-color: {R('panel_bg')};">
                <span style="font-size: 11px; color: {R('muted')};">Evidence Items</span><br>
                <span style="font-size: 17px; font-weight: bold; color: {R('text')};">{summary["evidence_records"]:,}</span><br>
                <span style="font-size: 10px; color: {R('muted')};">collected records</span></td>
              <td style="border: 1px solid {R('panel_border')}; border-radius: 6px; background-color: {R('panel_bg')};">
                <span style="font-size: 11px; color: {R('muted')};">Modules Scanned</span><br>
                <span style="font-size: 17px; font-weight: bold; color: {R('text')};">{html.escape(modules_count)}</span><br>
                <span style="font-size: 10px; color: {R('muted')};">{html.escape(modules_label)}</span></td>
              <td style="border: 1px solid {R('panel_border')}; border-radius: 6px; background-color: {R('panel_bg')}; white-space: nowrap;">
                <span style="font-size: 11px; color: {R('muted')};">Scan Status</span><br>
                <span style="font-size: 16px; font-weight: bold; color: {status_color};">{html.escape(status or "—")}</span><br>
                <span style="font-size: 10px; color: {R('muted')};">{html.escape(status_note)}</span></td>
            </tr>
          </table>
          <div style="font-weight: bold; font-size: 12px; margin: 10px 0 2px; color: {R('text')};">Findings by severity</div>
          <div>{wave_svg}</div>
          <table cellpadding="0" cellspacing="0" style="margin-top: 2px;"><tr>{"".join(bars)}</tr></table>
          {modules_html}
        </div>
        """

    def _populate_history_table(self, table, entries):
        """Fill a history table from session entries (newest first)."""
        table.setRowCount(len(entries))
        status_colors = {"COMPLETED": f"{R('ok_text')}", "PARTIAL": f"{R('warn_text')}", "ERROR": f"{R('err_text')}"}
        for row, entry in enumerate(entries):
            dot = "● " if entry["status"] == "COMPLETED" else "▲ " if entry["status"] == "PARTIAL" else "■ "
            values = [f"{dot}{entry['time']}", entry["scan_type"], entry["modules"],
                      str(entry["findings"]), f'{entry["evidence"]:,}',
                      entry["status"].capitalize() if entry["status"] else "—"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0 and entry["status"] in status_colors:
                    item.setForeground(QColor(status_colors[entry["status"]]))
                elif col == 5 and entry["status"] in status_colors:
                    item.setForeground(QColor(status_colors[entry["status"]]))
                table.setItem(row, col, item)

    def _build_history_dialog(self):
        """Build (but do not execute) the full session-history dialog."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Scan History — This Session")
        dialog.resize(720, 320)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Scans run in this session (newest first). "
                                "History is kept in memory only."))
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["Date & Time", "Scan Type", "Modules", "Findings", "Evidence Items", "Status"]
        )
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionMode(QTableWidget.NoSelection)
        self._populate_history_table(table, self._scan_history)
        layout.addWidget(table)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)
        return dialog

    def _open_history_dialog(self):
        self._build_history_dialog().exec()

    def init_my_footprint_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>My Footprint</h2>"))
        layout.addWidget(QLabel("Analyze information from your own system, browsers, and selected files."))

        # Sub-category tabs: System Footprint, Browser Footprint, File & Metadata Footprint
        self.my_footprint_tabs = QTabWidget()

        # -----------------------------
        # Tab 1: System Footprint
        # -----------------------------
        sys_tab = QWidget()
        sys_layout = QVBoxLayout(sys_tab)

        self.sys_scan_btn = QPushButton("System Footprint")
        self.sys_scan_btn.clicked.connect(self.start_system_scan)
        sys_layout.addWidget(self.sys_scan_btn)

        self.sys_status_label = QLabel("")
        self.sys_status_label.setWordWrap(True)
        sys_layout.addWidget(self.sys_status_label)

        self.sys_sub_tabs = QTabWidget()

        self.sys_findings_area = QTextBrowser()
        self.sys_findings_area.setOpenLinks(False)
        self.sys_findings_area.setReadOnly(True)
        self.sys_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.sys_findings_area.anchorClicked.connect(
            lambda url, key="sys": self._on_findings_anchor(key, url)
        )

        sys_evidence_tab = QWidget()
        sys_evidence_layout = QVBoxLayout(sys_evidence_tab)
        sys_evidence_layout.setContentsMargins(0, 0, 0, 0)

        sys_filter_row = QHBoxLayout()
        self.sys_evidence_search = QLineEdit()
        self.sys_evidence_search.setPlaceholderText("Filter evidence…")
        self.sys_evidence_search.setClearButtonEnabled(True)
        self.sys_evidence_search.textChanged.connect(
            lambda _text, key="sys": self._on_view_evidence_filter_changed(key)
        )
        sys_filter_row.addWidget(self.sys_evidence_search, stretch=1)

        self.sys_evidence_group = QComboBox()
        self.sys_evidence_group.addItems(["All groups", "Installed Applications",
                                          "Running Processes", "Startup Applications",
                                          "General info"])
        self.sys_evidence_group.currentIndexChanged.connect(
            lambda _index, key="sys": self._render_view_evidence(key)
        )
        sys_filter_row.addWidget(self.sys_evidence_group)
        sys_evidence_layout.addLayout(sys_filter_row)

        self.sys_results_area = QTextBrowser()
        self.sys_results_area.setOpenLinks(False)
        self.sys_results_area.setReadOnly(True)
        self.sys_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.sys_results_area.anchorClicked.connect(
            lambda url, key="sys": self._on_evidence_anchor(key, url)
        )
        sys_evidence_layout.addWidget(self.sys_results_area)

        self.sys_sub_tabs.addTab(self.sys_findings_area, "Findings")
        self.sys_sub_tabs.addTab(sys_evidence_tab, "Collected Evidence")
        sys_layout.addWidget(self.sys_sub_tabs)

        self.my_footprint_tabs.addTab(sys_tab, "System Footprint")

        # -----------------------------
        # Tab 2: Browser Footprint
        # -----------------------------
        browser_tab = QWidget()
        browser_layout = QVBoxLayout(browser_tab)

        self.browser_scan_btn = QPushButton("Browser Footprint")
        self.browser_scan_btn.clicked.connect(self.start_browser_scan)
        browser_layout.addWidget(self.browser_scan_btn)

        self.browser_status_label = QLabel("")
        self.browser_status_label.setWordWrap(True)
        browser_layout.addWidget(self.browser_status_label)

        self.browser_sub_tabs = QTabWidget()

        self.browser_findings_area = QTextBrowser()
        self.browser_findings_area.setOpenLinks(False)
        self.browser_findings_area.setReadOnly(True)
        self.browser_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.browser_findings_area.anchorClicked.connect(
            lambda url, key="browser": self._on_findings_anchor(key, url)
        )

        browser_evidence_tab = QWidget()
        browser_evidence_layout = QVBoxLayout(browser_evidence_tab)
        browser_evidence_layout.setContentsMargins(0, 0, 0, 0)

        browser_filter_row = QHBoxLayout()
        self.browser_evidence_search = QLineEdit()
        self.browser_evidence_search.setPlaceholderText("Filter evidence…")
        self.browser_evidence_search.setClearButtonEnabled(True)
        self.browser_evidence_search.textChanged.connect(
            lambda _text, key="browser": self._on_view_evidence_filter_changed(key)
        )
        browser_filter_row.addWidget(self.browser_evidence_search, stretch=1)

        self.browser_evidence_group = QComboBox()
        self.browser_evidence_group.addItems(["All groups", "Detected Browsers",
                                              "Extensions", "Coverage notes"])
        self.browser_evidence_group.currentIndexChanged.connect(
            lambda _index, key="browser": self._render_view_evidence(key)
        )
        browser_filter_row.addWidget(self.browser_evidence_group)
        browser_evidence_layout.addLayout(browser_filter_row)

        self.browser_results_area = QTextBrowser()
        self.browser_results_area.setOpenLinks(False)
        self.browser_results_area.setReadOnly(True)
        self.browser_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.browser_results_area.anchorClicked.connect(
            lambda url, key="browser": self._on_evidence_anchor(key, url)
        )
        browser_evidence_layout.addWidget(self.browser_results_area)

        self.browser_sub_tabs.addTab(self.browser_findings_area, "Findings")
        self.browser_sub_tabs.addTab(browser_evidence_tab, "Collected Evidence")
        browser_layout.addWidget(self.browser_sub_tabs)

        self.my_footprint_tabs.addTab(browser_tab, "Browser Footprint")

        # -----------------------------
        # Tab 3: File & Metadata Footprint
        # -----------------------------
        file_tab = QWidget()
        file_layout = QVBoxLayout(file_tab)

        file_desc = QLabel("Select a file to inspect embedded metadata (camera, GPS, author, software) and identify potentially sensitive information.")
        file_desc.setWordWrap(True)
        file_layout.addWidget(file_desc)

        file_select_row = QHBoxLayout()
        self.file_select_btn = QPushButton("Select File")
        self.file_select_btn.clicked.connect(self.select_file)
        file_select_row.addWidget(self.file_select_btn)

        self.selected_file_label = QLabel("No file selected")
        self.selected_file_label.setStyleSheet(f"color: {R('faint')};")
        file_select_row.addWidget(self.selected_file_label, stretch=1)

        self.file_analyze_btn = QPushButton("Analyze File")
        self.file_analyze_btn.setEnabled(False)
        self.file_analyze_btn.clicked.connect(self.start_file_analysis)
        file_select_row.addWidget(self.file_analyze_btn)

        file_layout.addLayout(file_select_row)

        self.file_status_label = QLabel("")
        self.file_status_label.setWordWrap(True)
        file_layout.addWidget(self.file_status_label)

        self.file_sub_tabs = QTabWidget()

        self.file_findings_area = QTextBrowser()
        self.file_findings_area.setOpenLinks(False)
        self.file_findings_area.setReadOnly(True)
        self.file_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.file_findings_area.anchorClicked.connect(
            lambda url, key="file": self._on_findings_anchor(key, url)
        )

        file_evidence_tab = QWidget()
        file_evidence_layout = QVBoxLayout(file_evidence_tab)
        file_evidence_layout.setContentsMargins(0, 0, 0, 0)

        file_filter_row = QHBoxLayout()
        self.file_evidence_search = QLineEdit()
        self.file_evidence_search.setPlaceholderText("Filter evidence…")
        self.file_evidence_search.setClearButtonEnabled(True)
        self.file_evidence_search.textChanged.connect(
            lambda _text, key="file": self._on_view_evidence_filter_changed(key)
        )
        file_filter_row.addWidget(self.file_evidence_search, stretch=1)

        self.file_evidence_group = QComboBox()
        self.file_evidence_group.addItems(["All groups", "File details",
                                           "Sensitive metadata", "Extracted metadata"])
        self.file_evidence_group.currentIndexChanged.connect(
            lambda _index, key="file": self._render_view_evidence(key)
        )
        file_filter_row.addWidget(self.file_evidence_group)
        file_evidence_layout.addLayout(file_filter_row)

        self.file_results_area = QTextBrowser()
        self.file_results_area.setOpenLinks(False)
        self.file_results_area.setReadOnly(True)
        self.file_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.file_results_area.anchorClicked.connect(
            lambda url, key="file": self._on_evidence_anchor(key, url)
        )
        file_evidence_layout.addWidget(self.file_results_area)

        self.file_sub_tabs.addTab(self.file_findings_area, "Findings")
        self.file_sub_tabs.addTab(file_evidence_tab, "Collected Evidence")
        file_layout.addWidget(self.file_sub_tabs)

        self.my_footprint_tabs.addTab(file_tab, "File & Metadata Footprint")

        # -----------------------------
        # Tab 4: Full Scan
        # -----------------------------
        full_tab = QWidget()
        full_layout = QVBoxLayout(full_tab)

        full_desc = QLabel("Run the System and Browser scans together in one background task. File Metadata is included only when you explicitly select a single file below.")
        full_desc.setWordWrap(True)
        full_layout.addWidget(full_desc)

        full_file_row = QHBoxLayout()
        self.full_scan_select_btn = QPushButton("Select File (Optional)")
        self.full_scan_select_btn.clicked.connect(self.select_full_scan_file)
        full_file_row.addWidget(self.full_scan_select_btn)

        self.full_scan_file_label = QLabel("No file selected")
        self.full_scan_file_label.setStyleSheet(f"color: {R('faint')};")
        full_file_row.addWidget(self.full_scan_file_label, stretch=1)

        self.full_scan_clear_btn = QPushButton("Clear")
        self.full_scan_clear_btn.setEnabled(False)
        self.full_scan_clear_btn.clicked.connect(self.clear_full_scan_file)
        full_file_row.addWidget(self.full_scan_clear_btn)

        full_layout.addLayout(full_file_row)

        self.full_scan_btn = QPushButton("Run Full Scan")
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        full_layout.addWidget(self.full_scan_btn)

        self.full_scan_status_label = QLabel("")
        self.full_scan_status_label.setWordWrap(True)
        full_layout.addWidget(self.full_scan_status_label)

        self.full_scan_sub_tabs = QTabWidget()

        self.full_scan_findings_area = QTextBrowser()
        self.full_scan_findings_area.setOpenLinks(False)
        self.full_scan_findings_area.setReadOnly(True)
        self.full_scan_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.full_scan_findings_area.anchorClicked.connect(
            lambda url, key="full": self._on_findings_anchor(key, url)
        )

        full_evidence_tab = QWidget()
        full_evidence_layout = QVBoxLayout(full_evidence_tab)
        full_evidence_layout.setContentsMargins(0, 0, 0, 0)

        full_filter_row = QHBoxLayout()
        self.full_evidence_search = QLineEdit()
        self.full_evidence_search.setPlaceholderText("Filter evidence…")
        self.full_evidence_search.setClearButtonEnabled(True)
        self.full_evidence_search.textChanged.connect(self._on_evidence_filter_changed)
        full_filter_row.addWidget(self.full_evidence_search, stretch=1)

        self.full_evidence_module = QComboBox()
        self.full_evidence_module.addItems(["All modules", "System", "Browser", "File & Metadata"])
        self.full_evidence_module.currentIndexChanged.connect(self._render_full_scan_evidence)
        full_filter_row.addWidget(self.full_evidence_module)

        full_evidence_layout.addLayout(full_filter_row)

        self.full_scan_results_area = QTextEdit()
        self.full_scan_results_area.setReadOnly(True)
        self.full_scan_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        full_evidence_layout.addWidget(self.full_scan_results_area)

        self.full_scan_sub_tabs.addTab(self.full_scan_findings_area, "Findings")
        self.full_scan_sub_tabs.addTab(full_evidence_tab, "Collected Evidence")
        full_layout.addWidget(self.full_scan_sub_tabs)

        self.my_footprint_tabs.addTab(full_tab, "Full Scan")

        layout.addWidget(self.my_footprint_tabs)
        self.pages.addWidget(page)

    def init_public_lookup_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Public Footprint Lookup</h2>"))

        # Input area
        input_layout = QHBoxLayout()
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Email", "Username"])

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter email or username...")
        self.target_input.returnPressed.connect(self.start_scan)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.start_scan)

        input_layout.addWidget(self.scan_type_combo)
        input_layout.addWidget(self.target_input)
        input_layout.addWidget(self.scan_btn)

        layout.addLayout(input_layout)

        # Privacy: this scan is the one place the app talks to third parties,
        # and the verification option decides whether it also reads the
        # candidate pages themselves.
        self.verify_candidates_checkbox = QCheckBox(
            "Verify each candidate by reading its public profile page")
        self.verify_candidates_checkbox.setChecked(True)
        self.verify_candidates_checkbox.setToolTip(
            "When checked, each platform hit is fetched once (unauthenticated) "
            "to check whether the page really shows this handle. Uncheck to "
            "keep the lookup to the discovery tool alone.")
        layout.addWidget(self.verify_candidates_checkbox)

        self.privacy_note = QLabel(
            "A Public Lookup contacts public platforms directly from this "
            "device. Nothing is uploaded to us, no account is signed in, and "
            "candidate pages are only read when verification is enabled above.")
        self.privacy_note.setWordWrap(True)
        self.register_themed_widget(self.privacy_note,
                                   "color: {muted}; font-size: 11px;")
        layout.addWidget(self.privacy_note)

        # Status
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Sub-tabs for Public Lookup
        self.public_sub_tabs = QTabWidget()

        self.public_findings_area = QTextBrowser()
        self.public_findings_area.setOpenLinks(False)
        self.public_findings_area.setReadOnly(True)
        self.public_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.public_findings_area.anchorClicked.connect(
            lambda url, key="public": self._on_findings_anchor(key, url)
        )

        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.public_sub_tabs.addTab(self.public_findings_area, "Findings")
        self.public_sub_tabs.addTab(self.results_area, "Collected Evidence")
        layout.addWidget(self.public_sub_tabs)

        self.pages.addWidget(page)

    # --------------------------------------------------------
    # THEME AND PREFERENCE CONTROL
    # --------------------------------------------------------

    def _detect_system_dark_mode(self):
        """Whether the host OS prefers a dark theme."""
        if sys.platform.startswith("win"):
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                )
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return value == 0
            except Exception:
                pass
        try:
            return self.palette().color(QPalette.ColorRole.Window).value() < 128
        except Exception:
            return False

    @property
    def is_dark_mode(self):
        """True when dark colors should be used right now."""
        if self.current_theme == "dark":
            return True
        if self.current_theme == "light":
            return False
        return self._detect_system_dark_mode()

    def set_theme_mode(self, mode):
        """Switch theme and persist the choice."""
        mode = str(mode).strip().lower()
        if mode not in ("system", "light", "dark"):
            return
        self.current_theme = mode
        self.app_settings.setValue("theme_mode", mode)
        self.apply_theme()

    def apply_theme(self):
        """Re-apply the palette, stylesheet, and every rendered view."""
        dark = self.is_dark_mode
        app = QApplication.instance()
        if app is not None:
            # Scope the stylesheet to this window: it covers every child
            # widget and dialog, without restyling unrelated windows.
            theme.apply_theme(app, dark=dark,
                              high_contrast=self.high_contrast,
                              font_scale=self.font_scale, target=self)
        else:
            theme.set_dark_theme(dark)
        self._refresh_home_theme()
        # Report HTML resolves colors through R() at build time, so every
        # rendered view must be rebuilt for a theme change to be visible.
        for view_key in ("sys", "browser", "file", "full", "public"):
            self._render_view_findings(view_key)
            self._render_view_evidence(view_key)

    def register_themed_widget(self, widget, template):
        """Apply a token-driven stylesheet and remember it for re-theming.

        Args:
            widget: the widget to style.
            template: a str.format template whose placeholders are token
                names (panel_bg, panel_bg_alt, panel_border, text, muted,
                faint, accent).
        """
        self._themed_widgets.append((widget, template))
        widget.setStyleSheet(self._render_theme_template(template))
        return widget

    @staticmethod
    def _render_theme_template(template):
        return theme.render_template(template)

    def _refresh_home_theme(self):
        """Restyle every registered widget and re-render themed HTML.

        Covers the sidebar, hero, scan cards, and checklist. The dashboard
        overview resolves colors through R() when its HTML is built, so it
        has to be rebuilt rather than restyled.
        """
        for widget, template in list(self._themed_widgets):
            try:
                widget.setStyleSheet(self._render_theme_template(template))
            except RuntimeError:
                # The underlying C++ widget was already destroyed.
                continue

        if hasattr(self, "dashboard_overview"):
            self.dashboard_overview.setHtml(
                self._format_dashboard_overview_html())

        # The expanded pages re-render their own token-based HTML; the widgets
        # themselves were registered above.
        for page in (getattr(self, "assessment_page", None),
                     getattr(self, "evidence_page", None),
                     getattr(self, "action_page", None),
                     getattr(self, "history_page", None)):
            if page is None:
                continue
            try:
                page.refresh_theme()
            except RuntimeError:
                continue
        self._refresh_home_assessment()

    def _render_view_findings(self, view_key):
        """Re-render one findings area from its held result."""
        result = self._last_results.get(view_key)
        if result is None:
            return
        area = getattr(self, f"{view_key}_findings_area", None)
        if area is None:
            return
        area.setHtml(self.format_findings_html(
            result.findings,
            evidence_count=len(result.footprint_data or []),
            scan_status=result.status,
            expanded=self._expanded_cards.get(view_key, set()),
            summary=summarize_full_scan(result) if view_key == "full" else None,
        ))

    def _render_view_evidence(self, view_key):
        """Re-render one collected-evidence area from its held result."""
        result = self._last_results.get(view_key)
        if result is None:
            return
        area = getattr(self, f"{view_key}_results_area", None)
        if area is None:
            return
        renderer = {
            "sys": self.format_system_evidence_html,
            "browser": self.format_browser_evidence_html,
            "file": self.format_file_evidence_html,
        }.get(view_key)
        if renderer is not None:
            area.setHtml(renderer(result.footprint_data))
        elif view_key == "full":
            area.setHtml(self.format_full_scan_evidence_html(result))
        elif view_key == "public":
            area.setHtml(self.format_public_evidence_html(
                result.footprint_data, result.findings))

    # --------------------------------------------------------
    # SETTINGS PAGE
    # --------------------------------------------------------

    def init_settings_page(self):
        """Build the Settings page: theme, scan engine, privacy, diagnostics."""
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(QLabel("<h2>Settings</h2>"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(12)

        # ----------------------------------------------------
        # Appearance & theming
        # ----------------------------------------------------
        appearance = QGroupBox("Appearance & Theming")
        appearance_layout = QVBoxLayout(appearance)
        appearance_layout.setSpacing(10)

        theme_desc = QLabel("Choose a color theme or follow your operating system:")
        theme_desc.setStyleSheet(f"color: {R('muted')};")
        appearance_layout.addWidget(theme_desc)

        self.theme_btn_group = QButtonGroup(self)
        theme_row = QHBoxLayout()
        theme_row.setSpacing(20)
        self.theme_system_rb = QRadioButton("System Default (Auto)")
        self.theme_light_rb = QRadioButton("Light Mode")
        self.theme_dark_rb = QRadioButton("Dark Mode")
        self.theme_btn_group.addButton(self.theme_system_rb, 0)
        self.theme_btn_group.addButton(self.theme_light_rb, 1)
        self.theme_btn_group.addButton(self.theme_dark_rb, 2)
        # Reflect the active mode. Toggling auto-refreshes the theme, which
        # keeps a saved preference and the selected control consistent.
        active_rb = {"light": self.theme_light_rb, "dark": self.theme_dark_rb}.get(
            self.current_theme, self.theme_system_rb)
        active_rb.setChecked(True)
        theme_row.addWidget(self.theme_system_rb)
        theme_row.addWidget(self.theme_light_rb)
        theme_row.addWidget(self.theme_dark_rb)
        theme_row.addStretch()
        appearance_layout.addLayout(theme_row)
        self.theme_system_rb.toggled.connect(
            lambda c: c and self._on_theme_radio_changed("system"))
        self.theme_light_rb.toggled.connect(
            lambda c: c and self._on_theme_radio_changed("light"))
        self.theme_dark_rb.toggled.connect(
            lambda c: c and self._on_theme_radio_changed("dark"))

        options_row = QHBoxLayout()
        options_row.setSpacing(20)
        self.contrast_checkbox = QCheckBox(
            "High-contrast text selection (blue with white text)")
        self.contrast_checkbox.setToolTip(
            "Removes white-on-white selection blocks and keeps selected text "
            "legible in both themes.")
        self.contrast_checkbox.setChecked(self.high_contrast)
        self.contrast_checkbox.toggled.connect(self._on_contrast_toggled)
        options_row.addWidget(self.contrast_checkbox)
        options_row.addSpacing(20)
        options_row.addWidget(QLabel("Text scale:"))
        self.font_scale_combo = QComboBox()
        self.font_scale_combo.addItems(
            ["Compact (12px)", "Standard (13px)", "Large (14px)",
             "Extra Large (16px)"])
        self.font_scale_combo.setCurrentIndex(
            {12: 0, 13: 1, 14: 2, 16: 3}.get(self.font_scale, 1))
        self.font_scale_combo.currentIndexChanged.connect(
            self._on_font_scale_changed)
        options_row.addWidget(self.font_scale_combo)
        options_row.addStretch()
        appearance_layout.addLayout(options_row)
        layout.addWidget(appearance)

        # ----------------------------------------------------
        # Scan & engine preferences
        # ----------------------------------------------------
        engine = QGroupBox("Scan & Engine Preferences")
        engine_layout = QVBoxLayout(engine)
        engine_layout.setSpacing(12)

        proc_row = QHBoxLayout()
        proc_lbl = QLabel("Windows process collector:")
        proc_lbl.setFixedWidth(200)
        self.process_mode_combo = QComboBox()
        self.process_mode_combo.addItems([
            "Fast & Resilient (tasklist with fallbacks)",
            "Standard (tasklist only)",
            "Deep query (adds executable paths)",
        ])
        self.process_mode_combo.setCurrentIndex(
            PROCESS_COLLECTOR_MODES.index(self.process_collector_mode))
        self.process_mode_combo.currentIndexChanged.connect(
            self._on_process_mode_changed)
        proc_row.addWidget(proc_lbl)
        proc_row.addWidget(self.process_mode_combo, stretch=1)
        engine_layout.addLayout(proc_row)

        preview_row = QHBoxLayout()
        preview_lbl = QLabel("Finding evidence preview cap:")
        preview_lbl.setFixedWidth(200)
        self.preview_limit_combo = QComboBox()
        self.preview_limit_combo.addItems([
            "5 entries per card",
            "10 entries per card (default)",
            "20 entries per card",
            "Unlimited (show all records)",
        ])
        self.preview_limit_combo.setCurrentIndex(
            {5: 0, 10: 1, 20: 2, 999999: 3}.get(
                self.evidence_preview_limit, 1))
        self.preview_limit_combo.currentIndexChanged.connect(
            self._on_preview_limit_changed)
        preview_row.addWidget(preview_lbl)
        preview_row.addWidget(self.preview_limit_combo, stretch=1)
        engine_layout.addLayout(preview_row)

        timeout_row = QHBoxLayout()
        timeout_lbl = QLabel("Public lookup network timeout:")
        timeout_lbl.setFixedWidth(200)
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems([
            "5 seconds (quick check)",
            "10 seconds (standard, recommended)",
            "20 seconds (deep lookup)",
        ])
        self.timeout_combo.setCurrentIndex(
            {5: 0, 10: 1, 20: 2}.get(self.network_timeout, 1))
        self.timeout_combo.currentIndexChanged.connect(self._on_timeout_changed)
        timeout_row.addWidget(timeout_lbl)
        timeout_row.addWidget(self.timeout_combo, stretch=1)
        engine_layout.addLayout(timeout_row)
        layout.addWidget(engine)

        # ----------------------------------------------------
        # Privacy & session controls
        # ----------------------------------------------------
        privacy = QGroupBox("Privacy & Session Controls")
        privacy_layout = QVBoxLayout(privacy)
        privacy_layout.setSpacing(10)

        cache_row = QHBoxLayout()
        self.cache_count_label = QLabel(self._get_cache_status_text())
        cache_row.addWidget(self.cache_count_label, stretch=1)
        clear_btn = QPushButton("Clear Cached Scan Results")
        clear_btn.setIcon(icon("layers"))
        clear_btn.clicked.connect(self.clear_all_cached_results)
        cache_row.addWidget(clear_btn)
        privacy_layout.addLayout(cache_row)

        self.settings_status_label = QLabel("")
        self.settings_status_label.setStyleSheet(f"color: {R('muted')};")
        self.settings_status_label.setWordWrap(True)
        privacy_layout.addWidget(self.settings_status_label)

        privacy_note = QFrame()
        privacy_note.setFrameShape(QFrame.NoFrame)
        privacy_note.setStyleSheet(
            f"QFrame {{ background-color: {R('panel_bg')}; "
            f"border: 1px solid {R('panel_border')}; border-radius: 6px; }}"
        )
        note_row = QHBoxLayout(privacy_note)
        note_row.setContentsMargins(10, 8, 10, 8)
        note_row.setSpacing(10)
        shield_icon = QLabel()
        shield_icon.setPixmap(pixmap("shield", 24))
        note_row.addWidget(shield_icon)
        note_text = QLabel(
            "<b>Local-first privacy:</b> system footprint scans, browser "
            "extension traces, and file metadata extraction all run locally on "
            "this computer. Only the Public Lookup checks you explicitly start "
            "contact external services.")
        note_text.setWordWrap(True)
        note_row.addWidget(note_text, stretch=1)
        privacy_layout.addWidget(privacy_note)
        layout.addWidget(privacy)

        # ----------------------------------------------------
        # Diagnostics
        # ----------------------------------------------------
        diagnostics = QGroupBox("System Diagnostics")
        diag_layout = QVBoxLayout(diagnostics)
        diag_layout.setSpacing(8)

        grid = QGridLayout()
        grid.setSpacing(8)
        try:
            import PySide6
            qt_ver = f"PySide6 {getattr(PySide6, '__version__', 'unknown')}"
        except Exception:
            qt_ver = "PySide6 (version unknown)"
        rows = [
            ("Application:", "Digital Footprint Analyzer v1.0.0"),
            ("Python runtime:",
             f"{platform.python_version()} ({platform.python_implementation()})"),
            ("GUI framework:", qt_ver),
            ("Host system:",
             f"{platform.system()} {platform.release()} ({platform.machine()})"),
            ("Active theme:",
             {"system": "System default", "light": "Light",
              "dark": "Dark"}.get(self.current_theme, self.current_theme)),
        ]
        for i, (label, value) in enumerate(rows):
            grid.addWidget(QLabel(f"<b>{label}</b>"), i, 0)
            grid.addWidget(QLabel(html.escape(str(value))), i, 1)
        diag_layout.addLayout(grid)

        reset_row = QHBoxLayout()
        reset_row.addStretch()
        self.reset_btn = QPushButton("Reset All Settings to Defaults")
        self.reset_btn.clicked.connect(self.reset_settings_to_defaults)
        reset_row.addWidget(self.reset_btn)
        diag_layout.addLayout(reset_row)
        layout.addWidget(diagnostics)
        layout.addStretch()

        scroll.setWidget(container)
        outer.addWidget(scroll)
        self.pages.addWidget(page)

    def init_expanded_pages(self):
        """Build the assessment, evidence, action, and history pages.

        They are appended after Settings so the original four pages keep their
        indices, and each one reads the shared RiskSummary / plan / stored
        records rather than computing anything of its own.
        """
        self.assessment_page = AssessmentPage(self)
        self.evidence_page = EvidencePage(self)
        self.action_page = ActionCentrePage(self)
        self.history_page = HistoryPage(self, store=self.history_store)

        for page in (self.assessment_page, self.evidence_page,
                     self.action_page, self.history_page):
            self.pages.addWidget(page)
            for widget, template in page.themed_widgets():
                self.register_themed_widget(widget, template)

        if self._history_error:
            self.history_page.report_storage_problem(self._history_error)

        self._refresh_home_assessment()

    def show_page(self, name):
        """Switch to one of the pages by name. Returns True when it exists."""
        order = ("home", "footprint", "public", "settings", "assessment",
                 "evidence", "actions", "history")
        key = str(name or "").strip().lower()
        if key not in order:
            return False
        index = order.index(key)
        if index >= self.pages.count():
            return False
        self.sidebar.setCurrentRow(index)
        self.pages.setCurrentIndex(index)
        return True

    def show_stored_findings(self, record):
        """Open a stored scan's findings in the evidence explorer."""
        self.evidence_page.show_findings(
            record.findings,
            source_label=f"stored scan {record.finished_at or ''}".strip())
        self.show_page("evidence")
        return True

    def on_action_state_changed(self, action_key, state):
        """Persist a mark the user made in the action centre."""
        if self.action_store is not None:
            try:
                if state == "forget":
                    self.action_store.forget(action_key)
                else:
                    self.action_store.set_state(action_key, state)
            except Exception as error:  # storage problems never crash the UI
                self.action_page.privacy_note.setText(
                    f"Could not save that change: {error}")
        self._refresh_actions()

    def _refresh_actions(self):
        """Rebuild the action board from the latest scan and stored marks."""
        if self.latest_result is None:
            self.action_page.set_board(None, plan=None)
            return
        plan = self.latest_plan
        if plan is None:
            plan = build_plan(self.latest_result)
            self.latest_plan = plan
        board = plan_with_states(plan, self.action_store)
        self.latest_board = board
        self.action_page.set_board(board, plan,
                                   state_handler=self.on_action_state_changed)
        # The dashboard strip reports the same pending count.
        self._refresh_home_assessment()

    def _record_scan_assessment(self, result):
        """Score, plan, and store one finished scan.

        This is the single place a finished scan becomes an assessment. Every
        page, the exports, and the history read the same objects produced
        here. Storage failures are reported in the UI, never raised.
        """
        try:
            risk = build_risk_summary(result)
        except Exception as error:  # a scoring bug must not hide the scan
            self.assessment_page.subtitle_label.setText(
                f"The assessment could not be built: {error}")
            return

        self.latest_risk = risk
        self.latest_result = result
        self.latest_plan = build_plan(result)

        target = None
        if (result.scan_type or "") in ("Email", "Username"):
            target = self.target_input.text().strip() or None

        if self.history_store is not None:
            try:
                self.history_store.record_scan(result, risk_summary=risk,
                                               target=target)
                self.history_page.storage_problem = ""
            except HistoryStoreError as error:
                self.history_page.report_storage_problem(
                    f"Could not store this scan: {error}")

        self.assessment_page.set_assessment(result, risk, target=target,
                                            plan=self.latest_plan,
                                            board=None)
        self.evidence_page.show_result(result, source_label="Current scan")
        self._refresh_actions()
        self.history_page.refresh()
        self._refresh_home_assessment()

    def _refresh_home_assessment(self):
        """Update the Home risk strip and pending-action count."""
        if not hasattr(self, "home_risk_label"):
            return

        muted = R("muted")
        risk = self.latest_risk
        if risk is None:
            self.home_risk_label.setText(
                f"<span style='color: {muted};'>No scan yet. Run a scan to get "
                "an exposure assessment.</span>")
        else:
            if risk.score is None:
                score_text = "No score"
                color = muted
                reason = (f" — {html.escape(risk.unavailable_reason)}"
                          if risk.unavailable_reason else "")
            else:
                score_text = f"{risk.score}/100"
                color = R("sev_critical") if risk.score >= 76 else (
                    R("sev_high") if risk.score >= 51 else (
                        R("sev_medium") if risk.score >= 25 else (
                            R("sev_low") if risk.score >= 1 else R("ok_text"))))
                reason = ""
            self.home_risk_label.setText(
                f"<span style='font-size: 22px; font-weight: bold; color: {color};'>"
                f"{score_text}</span> "
                f"<b>{html.escape(risk.band)}</b> "
                f"<span style='color: {muted};'>· confidence "
                f"{html.escape(risk.confidence)} · "
                f"{risk.counts.get('distinct_issues', 0)} distinct issue(s)"
                f"{reason}</span>")

        pending = self.latest_board.pending if self.latest_board else None
        if pending is None:
            actions_text = f"<span style='color: {muted};'>No actions yet.</span>"
        elif pending == 0:
            actions_text = f"<span style='color: {R('ok_text')};'>Nothing pending.</span>"
        else:
            actions_text = (f"<span style='color: {R('warn_text')};'><b>{pending}</b> "
                            "action(s) pending.</span>")
        self.home_actions_label.setText(actions_text)

    def _open_assessment(self):
        self.show_page("assessment")

    def _open_actions_page(self):
        self.show_page("actions")

    def _open_history_page(self):
        self.show_page("history")

    def _on_theme_radio_changed(self, mode):
        self.set_theme_mode(mode)
        self._notify_settings_changed(f"Theme updated to {mode}.")

    def _on_contrast_toggled(self, checked):
        self.high_contrast = bool(checked)
        self.app_settings.setValue("high_contrast_selection", self.high_contrast)
        self.apply_theme()
        self._notify_settings_changed(
            "High-contrast selection enabled" if self.high_contrast
            else "Standard selection enabled")

    def _on_font_scale_changed(self, index):
        scales = [12, 13, 14, 16]
        if 0 <= index < len(scales):
            self.font_scale = scales[index]
            self.app_settings.setValue("font_scale", self.font_scale)
            self.apply_theme()
            self._notify_settings_changed(
                f"Text scale set to {self.font_scale}px")

    def _on_process_mode_changed(self, index):
        if 0 <= index < len(PROCESS_COLLECTOR_MODES):
            self.process_collector_mode = PROCESS_COLLECTOR_MODES[index]
            self.app_settings.setValue(
                "process_collector_mode", self.process_collector_mode)
            self._notify_settings_changed("Process collector saved")

    def _on_preview_limit_changed(self, index):
        limits = [5, 10, 20, 999999]
        if 0 <= index < len(limits):
            self.evidence_preview_limit = limits[index]
            self.app_settings.setValue(
                "evidence_preview_limit", self.evidence_preview_limit)
            self._notify_settings_changed("Evidence preview cap updated")
            for view_key in ("sys", "browser", "file", "full", "public"):
                self._render_view_findings(view_key)

    def _on_timeout_changed(self, index):
        timeouts = [5, 10, 20]
        if 0 <= index < len(timeouts):
            self.network_timeout = timeouts[index]
            self.app_settings.setValue("network_timeout", self.network_timeout)
            self._notify_settings_changed(
                f"Lookup timeout set to {self.network_timeout}s")

    def _notify_settings_changed(self, message):
        if hasattr(self, "settings_status_label"):
            self.settings_status_label.setText(html.escape(str(message)))

    def _get_cache_status_text(self):
        count = sum(1 for v in self._last_results.values() if v is not None)
        if not count:
            return "No scan results are held in memory."
        return f"{count} scan result(s) held in memory for this session."

    def clear_all_cached_results(self):
        """Drop every in-memory scan result and reset the affected views."""
        self._last_results.clear()
        self._expanded_cards.clear()
        self._collapsed_evidence.clear()
        self._expanded_evidence_records.clear()

        for attr in ("sys_findings_area", "sys_results_area",
                     "browser_findings_area", "browser_results_area",
                     "file_findings_area", "file_results_area",
                     "full_scan_findings_area", "full_scan_results_area",
                     "public_findings_area", "results_area"):
            area = getattr(self, attr, None)
            if area is not None:
                area.clear()

        # Sub-tab titles carry the old counts, so reset them too.
        for tabs_name, key in (("sys_sub_tabs", "sys"),
                               ("browser_sub_tabs", "browser"),
                               ("file_sub_tabs", "file"),
                               ("full_scan_sub_tabs", "full"),
                               ("public_sub_tabs", "public")):
            tabs = getattr(self, tabs_name, None)
            if tabs is not None:
                tabs.setTabText(0, "Findings")
                tabs.setTabText(1, "Collected Evidence")

        for attr in ("sys_status_label", "browser_status_label",
                     "file_status_label", "full_scan_status_label",
                     "status_label"):
            label = getattr(self, attr, None)
            if label is not None:
                label.setText("")

        # The Full Scan file selection is also session state.
        self.full_scan_file_path = None
        self.full_scan_file_label.setText("No file selected")
        self.full_scan_clear_btn.setEnabled(False)

        self._refresh_dashboard_cache_state()
        if hasattr(self, "cache_count_label"):
            self.cache_count_label.setText(self._get_cache_status_text())
        self._notify_settings_changed("All in-memory scan results cleared.")

    def _refresh_dashboard_cache_state(self):
        """Drop dashboard history that referenced the cleared results."""
        self._scan_history = []
        self._dashboard_summary = None

    def reset_settings_to_defaults(self):
        """Restore every preference and theme option to its default."""
        self.current_theme = "dark"
        self.high_contrast = True
        self.font_scale = 13
        self.evidence_preview_limit = FINDING_EVIDENCE_PREVIEW_LIMIT
        self.process_collector_mode = DEFAULT_PROCESS_COLLECTOR_MODE
        self.network_timeout = 10

        self.app_settings.clear()
        self.apply_theme()

        # Keep the controls in sync with the restored values.
        self.theme_dark_rb.setChecked(True)
        self.contrast_checkbox.setChecked(True)
        self.font_scale_combo.setCurrentIndex(1)
        self.process_mode_combo.setCurrentIndex(
            PROCESS_COLLECTOR_MODES.index(DEFAULT_PROCESS_COLLECTOR_MODE))
        self.preview_limit_combo.setCurrentIndex(
            {5: 0, 10: 1, 20: 2, 999999: 3}.get(
                self.evidence_preview_limit, 1))
        self.timeout_combo.setCurrentIndex(1)
        self._notify_settings_changed("Settings reset to defaults.")

    def change_page(self, index):
        self.pages.setCurrentIndex(index)

    def start_system_scan(self):
        if self.worker and self.worker.isRunning():
            return

        self.sys_scan_btn.setEnabled(False)
        self.sys_status_label.setText("Scanning system footprint... Please wait, this may take a moment.")
        self.sys_findings_area.clear()
        self.sys_results_area.clear()
        self.sys_sub_tabs.setTabText(0, "Findings")
        self.sys_sub_tabs.setTabText(1, "Collected Evidence")

        self.worker = ScanWorker(
            "System", "",
            options={"process_mode": self.process_collector_mode})
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def start_browser_scan(self):
        if self.worker and self.worker.isRunning():
            return

        self.browser_scan_btn.setEnabled(False)
        self.browser_status_label.setText("Scanning browsers... Please wait.")
        self.browser_findings_area.clear()
        self.browser_results_area.clear()
        self.browser_sub_tabs.setTabText(0, "Findings")
        self.browser_sub_tabs.setTabText(1, "Collected Evidence")

        self.worker = ScanWorker("Browser", "")
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return

        target = self.target_input.text().strip()
        scan_type = self.scan_type_combo.currentText()

        if not target:
            self.status_label.setText("Error: Input cannot be empty.")
            return

        self.scan_btn.setEnabled(False)
        self.status_label.setText(f"Scanning {scan_type.lower()}... Please wait.")
        self.public_findings_area.clear()
        self.results_area.clear()
        self.public_sub_tabs.setTabText(0, "Findings")
        self.public_sub_tabs.setTabText(1, "Collected Evidence")

        self.worker = ScanWorker(
            scan_type, target,
            options={"network_timeout": float(self.network_timeout),
                     "verify_candidates":
                         self.verify_candidates_checkbox.isChecked()})
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Metadata Analysis",
            "",
            "All Supported Images (*.jpg *.jpeg *.png);;JPEG Images (*.jpg *.jpeg);;PNG Images (*.png);;All Files (*)"
        )
        if file_path:
            self.selected_file_path = file_path
            self.selected_file_label.setText(os.path.basename(file_path))
            self.selected_file_label.setStyleSheet(f"color: {R('black_text')}; font-weight: bold;")
            self.file_analyze_btn.setEnabled(True)
            self.file_status_label.setText("File selected. Click 'Analyze File' to extract metadata.")
            self.file_findings_area.clear()
            self.file_results_area.clear()
            self.file_sub_tabs.setTabText(0, "Findings")
            self.file_sub_tabs.setTabText(1, "Collected Evidence")
        else:
            if not getattr(self, 'selected_file_path', None):
                self.file_status_label.setText("File selection cancelled.")

    def start_file_analysis(self):
        if self.worker and self.worker.isRunning():
            return

        file_path = getattr(self, 'selected_file_path', None)
        if not file_path:
            self.file_status_label.setText("Error: No file selected. Please select a file first.")
            return

        self.file_select_btn.setEnabled(False)
        self.file_analyze_btn.setEnabled(False)
        self.file_status_label.setText("Analyzing file metadata... Please wait.")
        self.file_findings_area.clear()
        self.file_results_area.clear()
        self.file_sub_tabs.setTabText(0, "Findings")
        self.file_sub_tabs.setTabText(1, "Collected Evidence")

        self.worker = ScanWorker("File & Metadata", file_path)
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def select_full_scan_file(self):
        # Explicit opt-in only: selecting a file never starts a scan.
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Full Scan (Optional)",
            "",
            "All Supported Images (*.jpg *.jpeg *.png);;JPEG Images (*.jpg *.jpeg);;PNG Images (*.png);;All Files (*)"
        )
        if file_path:
            self.full_scan_file_path = file_path
            self.full_scan_file_label.setText(os.path.basename(file_path))
            self.full_scan_file_label.setStyleSheet(f"color: {R('black_text')}; font-weight: bold;")
            self.full_scan_clear_btn.setEnabled(True)
            self.full_scan_status_label.setText("File selected. Click 'Run Full Scan' to include it; otherwise System and Browser scans run without File Metadata.")

    def clear_full_scan_file(self):
        self.full_scan_file_path = None
        self.full_scan_file_label.setText("No file selected")
        self.full_scan_file_label.setStyleSheet(f"color: {R('faint')};")
        self.full_scan_clear_btn.setEnabled(False)

    def start_full_scan(self):
        if self.worker and self.worker.isRunning():
            return

        self.full_scan_btn.setEnabled(False)
        self.full_scan_select_btn.setEnabled(False)
        self.full_scan_clear_btn.setEnabled(False)
        self.full_scan_status_label.setText("Starting Full Scan... System and Browser scans will run; File Metadata runs only if a file was selected.")
        self.full_scan_findings_area.clear()
        self.full_scan_results_area.clear()
        self.full_scan_sub_tabs.setTabText(0, "Findings")
        self.full_scan_sub_tabs.setTabText(1, "Collected Evidence")

        self.worker = ScanWorker("Full Scan", self.full_scan_file_path or "")
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.progress_changed.connect(self.on_full_scan_progress)
        self.worker.start()

    def on_full_scan_progress(self, message):
        # Only Full Scan emits progress; ignore anything unexpected so an
        # individual scan's status labels can never be overwritten here.
        if self.worker and getattr(self.worker, 'scan_type', '') == "Full Scan":
            self.full_scan_status_label.setText(message)

    def _findings_area_for(self, view_key):
        return {
            "sys": getattr(self, "sys_findings_area", None),
            "browser": getattr(self, "browser_findings_area", None),
            "file": getattr(self, "file_findings_area", None),
            "public": getattr(self, "public_findings_area", None),
            "full": getattr(self, "full_scan_findings_area", None),
        }.get(view_key)

    def _on_findings_anchor(self, view_key, url):
        """Expand or collapse a finding's evidence list in place.

        Links have the form "#ev-<card-index>-show|hide". Re-rendering goes
        through the normal completion path with the stored result, so button
        states, labels, and tab counts stay consistent; only the expanded
        set for this view changes.
        """
        try:
            fragment = url.fragment()
        except AttributeError:
            return
        parts = (fragment or "").split("-")
        if len(parts) != 3 or parts[0] != "ev":
            return
        try:
            index = int(parts[1])
        except ValueError:
            return
        if parts[2] not in ("show", "hide"):
            return
        result = self._last_results.get(view_key)
        if result is None:
            return
        expanded = self._expanded_cards.setdefault(view_key, set())
        if parts[2] == "show":
            expanded.add(index)
        else:
            expanded.discard(index)
        area = self._findings_area_for(view_key)
        scrollbar = area.verticalScrollBar().value() if area is not None else 0
        self.on_scan_complete(result)
        if area is not None:
            area.verticalScrollBar().setValue(scrollbar)

    def _full_evidence_module_filter(self):
        text = self.full_evidence_module.currentText()
        return "All" if text == "All modules" else text

    def _on_evidence_filter_changed(self):
        self._schedule_evidence_render("full")

    def _schedule_evidence_render(self, view_key):
        # Debounce keystrokes so large evidence sets are not re-rendered
        # on every character typed.
        self._pending_evidence_view = view_key
        if self._evidence_filter_timer is None:
            self._evidence_filter_timer = QTimer(self)
            self._evidence_filter_timer.setSingleShot(True)
            self._evidence_filter_timer.timeout.connect(self._render_pending_evidence)
        self._evidence_filter_timer.start(250)

    def _render_pending_evidence(self):
        if self._pending_evidence_view:
            self._render_view_evidence(self._pending_evidence_view)

    def _on_view_evidence_filter_changed(self, view_key):
        # A new filter defines a new visible record set, so per-record and
        # group expansion state for this view is reset before re-rendering.
        self._collapsed_evidence[view_key] = set()
        self._expanded_evidence_records[view_key] = set()
        self._schedule_evidence_render(view_key)

    def _on_evidence_anchor(self, view_key, url):
        """Toggle evidence group collapse or record details in place.

        Links have the form "#evd-<view>-g-<group>" for groups and
        "#evd-<view>-<group>:<index>-show|hide" for records. Only the
        evidence area re-renders; findings, buttons, and labels are untouched.
        """
        try:
            fragment = url.fragment()
        except AttributeError:
            return
        prefix = f"evd-{view_key}-"
        if not (fragment or "").startswith(prefix):
            return
        rest = fragment[len(prefix):]
        area = {
            "sys": getattr(self, "sys_results_area", None),
            "browser": getattr(self, "browser_results_area", None),
            "file": getattr(self, "file_results_area", None),
            "full": getattr(self, "full_scan_results_area", None),
        }.get(view_key)
        if area is None:
            return
        if rest.startswith("g-"):
            group = rest[2:]
            if not group:
                return
            collapsed = self._collapsed_evidence.setdefault(view_key, set())
            if group in collapsed:
                collapsed.discard(group)
            else:
                collapsed.add(group)
            self._expanded_evidence_records[view_key] = set()
        else:
            try:
                group_index, action = rest.rsplit("-", 1)
                group, index_text = group_index.split(":")
                index = int(index_text)
            except ValueError:
                return
            if action not in ("show", "hide"):
                return
            expanded = self._expanded_evidence_records.setdefault(view_key, set())
            key = f"{group}:{index}"
            if action == "show":
                expanded.add(key)
            else:
                expanded.discard(key)
        scrollbar = area.verticalScrollBar().value()
        self._render_view_evidence(view_key)
        area.verticalScrollBar().setValue(scrollbar)

    def _view_evidence_filter(self, view_key):
        """Read the active search/group filter widgets for an evidence view."""
        search = getattr(self, f"{view_key}_evidence_search", None)
        combo = getattr(self, f"{view_key}_evidence_group", None)
        query = search.text() if search is not None else ""
        choice = combo.currentText() if combo is not None else "All groups"
        if view_key == "full":
            module = "All" if choice == "All modules" else choice
            return query, module, None, None
        groups = _VIEW_GROUP_FILTERS.get(view_key, {}).get(choice)
        if groups is None:
            return query, "All", None, None
        subcategories, exclude = groups
        return query, "All", subcategories, exclude

    def _render_view_evidence(self, view_key):
        """Re-render one evidence area from its held result and filters."""
        result = self._last_results.get(view_key)
        if result is None:
            return
        if view_key == "full":
            self._render_full_scan_evidence()
            return
        query, module, subcategories, exclude = self._view_evidence_filter(view_key)
        footprint = result.footprint_data or []
        visible = filter_footprint(footprint, query=query, module=module,
                                   subcategories=subcategories,
                                   exclude_subcategories=exclude)
        collapsed = self._collapsed_evidence.get(view_key, set())
        expanded_records = self._expanded_evidence_records.get(view_key, set())
        if view_key == "sys":
            body = self.format_system_evidence_html(
                visible, view_key="sys", collapsed=collapsed,
                expanded_records=expanded_records)
            area = self.sys_results_area
        elif view_key == "browser":
            body = self.format_browser_evidence_html(
                visible, view_key="browser", collapsed=collapsed,
                expanded_records=expanded_records)
            area = self.browser_results_area
        elif view_key == "file":
            body = self.format_file_evidence_html(
                visible, view_key="file", collapsed=collapsed,
                expanded_records=expanded_records)
            area = self.file_results_area
        else:
            return
        if query or subcategories is not None or exclude is not None:
            body = filter_note_html(len(visible), len(footprint)) + body
        if not visible and footprint:
            body += (f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; '
                     'border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; '
                     f'color: {R("subtle")};">No records match the current filter. Clear the search '
                     'or choose a different group to see more evidence.</div>')
        area.setHtml(body)

    def _render_full_scan_evidence(self):
        result = self._last_results.get("full")
        if result is None:
            return
        self.full_scan_results_area.setHtml(self.format_full_scan_evidence_html(
            result,
            query=self.full_evidence_search.text(),
            module=self._full_evidence_module_filter(),
        ))

    # --------------------------------------------------------
    # HTML FORMATTERS FOR FINDINGS AND COLLECTED EVIDENCE
    # --------------------------------------------------------

    def format_findings_html(self, findings, evidence_count=0, scan_status=None,
                               expanded=frozenset(), summary=None,
                               preview_limit=None):
        if preview_limit is None:
            preview_limit = self.evidence_preview_limit
        """Formats the list of Finding objects into structured, restrained HTML cards with scan summary.

        Counting rules: total/concern/observation counts describe findings
        only; evidence_count must be len(ScanResult.footprint_data), i.e. the
        number of records rendered in Collected Evidence. Finding evidence
        entries are never added to that count.

        Coverage-type findings (scan coverage, unavailable sources, warnings,
        limitations) render in a dedicated section below the regular cards.
        Card indices in expanded links refer to positions in findings.
        An optional read-only summary dict from summarize_full_scan() adds
        severity chips and per-module outcome rows.
        """
        findings = list(findings) if findings else []
        expanded = set(expanded) if expanded else set()
        total_findings = len(findings)
        concerns_count = sum(1 for f in findings if (getattr(f, "category", "") or "") == "Concern")
        observations_count = total_findings - concerns_count
        limitation_count = sum(1 for f in findings if (getattr(f, "finding_type", "") or "") == "Scan Limitation")
        severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
        for f in findings:
            sev = (f.severity or "Info").strip().capitalize()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        regular = [(i, f) for i, f in enumerate(findings)
                   if (getattr(f, "finding_type", "") or "") not in COVERAGE_FINDING_TYPES]
        coverage = [(i, f) for i, f in enumerate(findings)
                    if (getattr(f, "finding_type", "") or "") in COVERAGE_FINDING_TYPES]

        # Overall scan status banner: keeps PARTIAL/ERROR distinguishable from
        # a clean COMPLETED scan without implying exposure by itself.
        status_banner = ""
        if scan_status:
            status_styles = {
                "COMPLETED": (f"{R('ok_text')}", f"{R('ok_bg')}", f"{R('ok_border')}"),
                "PARTIAL": (f"{R('warn_text')}", f"{R('warn_bg')}", f"{R('warn_border')}"),
                "ERROR": (f"{R('err_text')}", f"{R('err_bg')}", f"{R('err_border')}"),
            }
            status_key = str(scan_status).strip().upper()
            text_color, bg_color, border_color = status_styles.get(
                status_key, (f"{R('muted')}", f"{R('panel_bg_alt')}", f"{R('panel_border')}")
            )
            guidance = SCAN_STATUS_GUIDANCE.get(status_key, "")
            guidance_html = (
                f'<span style="color: {R('muted')};"> — {html.escape(guidance)}</span>'
                if guidance else ""
            )
            status_banner = f"""
        <div style="font-family: sans-serif; margin-bottom: 8px; padding: 6px 12px; background-color: {bg_color}; border: 1px solid {border_color}; border-radius: 6px; font-size: 12px; color: {text_color};">
            <b>Scan Status:</b> {html.escape(status_key)}{guidance_html}
        </div>
        """

        # Severity chips: every tier is shown so groupings stay visible even
        # at zero; dimmed chips mark empty tiers.
        severity_chips = []
        for sev in SEVERITY_ORDER:
            count = severity_counts.get(sev, 0)
            chip_style = (
                f"background-color: {R('panel_border')}; color: {R('text')};"
                if count else f"background-color: {R('panel_bg_alt')}; color: {R('faint_alt')};"
            )
            severity_chips.append(
                f'<span style="{chip_style} font-weight: bold; padding: 2px 6px; '
                f'border-radius: 3px; font-size: 11px; margin-right: 4px;">'
                f'{html.escape(sev)}: {count}</span>'
            )
        severity_row = f"""
        <div style="font-family: sans-serif; margin-bottom: 8px; font-size: 12px; color: {R('text_alt')};">
            <b>By severity:</b> {"&nbsp;&nbsp;".join(severity_chips)}
        </div>
        """

        # Per-module outcome rows supplied by the display summary, if any.
        module_rows = ""
        if summary and summary.get("modules"):
            state_styles = {
                "completed": (f"{R('ok_text')}", "✓"),
                "limited": (f"{R('warn_text')}", "⚠"),
                "failed": (f"{R('err_text')}", "✕"),
                "skipped": (f"{R('muted')}", "⊘"),
                "unknown": (f"{R('faint_alt')}", "?"),
            }
            row_lines = []
            for mod in summary["modules"]:
                color, mark = state_styles.get(
                    mod.get("state", "unknown"), (f"{R('faint_alt')}", "?")
                )
                row_lines.append(
                    f'<div style="font-size: 12px; margin-bottom: 2px; color: {R('text_alt')};">'
                    f'<span style="color: {color}; font-weight: bold;">{mark}</span> '
                    f'<b>{html.escape(mod.get("name", "?"))}:</b> '
                    f'{html.escape(mod.get("note", ""))}</div>'
                )
            module_rows = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {R('card_bg')}; border: 1px solid {R('panel_border')}; border-radius: 6px;">
            <div style="font-size: 12px; font-weight: bold; color: {R('text')}; margin-bottom: 4px;">Modules:</div>
            {"".join(row_lines)}
        </div>
        """

        # Limitations are scan-coverage notes, never privacy exposures.
        limitation_note = ""
        if limitation_count > 0:
            limitation_note = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {R('panel_bg_alt')}; border: 1px dotted {R('dotted_border')}; border-radius: 6px; font-size: 11px; color: {R('muted')};">
            <b>Scan Limitations ({limitation_count}):</b> notes about sources that could not be checked
            (unsupported platforms, locked profiles, or failed modules). These describe scan coverage,
            not confirmed privacy exposures.
        </div>
        """

        # Build Scan Summary Header Banner. Pills flow inline so the summary
        # wraps gracefully on narrow windows instead of squeezing one row.
        summary_html = f"""
        {status_banner}
        {severity_row}
        {module_rows}
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {R('panel_bg')}; border: 1px solid {R('panel_border')}; border-radius: 6px; font-size: 12px; color: {R('text_alt')}; line-height: 2;">
            <b>SCAN SUMMARY:</b>
            <span style="margin-left: 8px;"><b>Total Findings:</b> <span style="background-color: {R('panel_border')}; color: {R('text')}; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{total_findings}</span></span>
            <span style="margin-left: 8px;"><b>Concerns:</b> <span style="background-color: {R('err_bg')}; color: {R('err_text')}; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{concerns_count}</span></span>
            <span style="margin-left: 8px;"><b>Observations:</b> <span style="background-color: {R('info_bg')}; color: {R('link')}; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{observations_count}</span></span>
            <span style="margin-left: 8px;"><b>Evidence Items:</b> <span style="background-color: {R('panel_bg_alt')}; color: {R('chip_text')}; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{evidence_count}</span></span>
        </div>
        {limitation_note}
        """

        if not findings:
            failure_note = ""
            if scan_status and str(scan_status).strip().upper() == "ERROR":
                failure_note = f"""
                <div style="padding: 12px; border: 1px solid {R('err_border')}; border-radius: 6px; background-color: {R('err_bg')}; color: {R('err_text_strong')}; margin-top: 4px; font-size: 12px;">
                    <b>The scan did not complete.</b> No findings could be produced because the
                    scan itself failed — this is not a clean bill of health. Check the status
                    message for details and try running the scan again.
                </div>
                """
            return f"""
            <div style="font-family: sans-serif; padding: 4px;">
                {summary_html}
                {failure_note}
                <div style="padding: 16px; border: 1px dashed {R('empty_box_muted')}; border-radius: 6px; background-color: {R('empty_box_bg')}; color: {R('empty_box_text')}; margin-top: 4px;">
                    <h3 style="margin-top: 0; color: {R('empty_box_heading')}; font-size: 14px;">No findings were generated for this scan.</h3>
                    <p style="margin-bottom: 0; font-size: 12px; color: {R('empty_box_muted')}; line-height: 1.4;">
                        All evaluated rule conditions were negative for positive exposure evidence.<br>
                        <i>Note: An absence of findings indicates that no supported rule conditions were met, but does not guarantee the system or identifier is free of all privacy or security exposure.</i>
                    </p>
                </div>
            </div>
            """

        cards = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            summary_html,
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {R('text_alt')};">=== FINDINGS ({total_findings} detected) ===</div>'
        ]

        for card_index, f in regular:
            cat = getattr(f, "category", "Observation") or "Observation"
            sev = f.severity or "Info"
            rule_id = getattr(f, "rule_id", None)
            limitations = getattr(f, "limitations", None)

            # Restrained, distinct badge and border color palette
            is_concern = (cat == "Concern")
            if is_concern:
                cat_badge_bg = f"{R('sev_critical')}" if sev in ("High", "Critical") else f"{R('sev_medium')}"
                card_border = f"{R('sev_critical')}" if sev in ("High", "Critical") else f"{R('sev_medium')}"
                card_bg = f"{R('card_bg_concern_high')}" if sev in ("High", "Critical") else f"{R('card_bg_concern_med')}"
                title_color = f"{R('err_text')}" if sev in ("High", "Critical") else f"{R('warn_text')}"
            else:
                cat_badge_bg = f"{R('link')}"
                card_border = f"{R('link')}"
                card_bg = f"{R('card_bg')}"
                title_color = f"{R('link')}"

            sev_colors = {
                "Critical": f"{R('sev_critical')}",
                "High": f"{R('sev_critical')}",
                "Medium": f"{R('sev_medium')}",
                "Low": f"{R('sev_low')}",
                "Info": f"{R('link')}"
            }
            sev_bg = sev_colors.get(sev, f"{R('link')}")

            sev_guidance = SEVERITY_GUIDANCE.get(sev, f"{sev} · for awareness")
            cat_guidance = ("Potential concern" if cat == "Concern"
                            else "Informational observation")
            evidence_count_for_card = len(collect_finding_evidence_items(f.evidence))
            evidence_block = format_finding_evidence_html(
                f.evidence, preview_limit=preview_limit,
                expanded=(card_index in expanded), card_index=card_index
            )
            evidence_heading = (
                f"Evidence ({evidence_count_for_card} "
                f"entr{'y' if evidence_count_for_card == 1 else 'ies'}):"
                if evidence_count_for_card
                else "Evidence:"
            )

            rule_html = f'<span style="font-size: 11px; color: {R('faint_meta')}; font-family: monospace;">Rule: {html.escape(rule_id)}</span>' if rule_id else ""
            limitations_html = (
                f'<div style="font-size: 11px; color: {R('muted')}; font-style: italic; margin-top: 5px; padding-top: 4px; border-top: 1px dotted {R('panel_border')};">'
                f'<b>Scope Limitation:</b> {html.escape(limitations)}</div>'
            ) if limitations else ""

            card = f"""
            <div style="border: 1px solid {R('panel_border')}; border-left: 4px solid {card_border}; border-radius: 4px; background-color: {card_bg}; padding: 6px 10px; margin-bottom: 8px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 4px;">
                    <tr>
                        <td align="left">
                            <span style="background-color: {cat_badge_bg}; color: {R('white')}; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 3px;">{html.escape(cat.upper())}</span>
                            <span style="background-color: {sev_bg}; color: {R('white')}; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 3px; margin-left: 4px;">{html.escape(sev.upper())}</span>
                        </td>
                        <td align="right">
                            {rule_html}
                        </td>
                    </tr>
                </table>
                <div style="font-size: 13px; font-weight: bold; color: {title_color}; margin-bottom: 3px;">
                    {html.escape(f.title)}
                </div>
                <div style="font-size: 11px; color: {R('muted')}; margin-bottom: 4px;">
                    {html.escape(sev_guidance)} · {html.escape(cat_guidance)}
                </div>
                <div style="font-size: 12px; color: {R('text')}; line-height: 1.4; margin-bottom: 4px;">
                    {html.escape(f.description)}
                </div>
                <div style="background-color: {R('panel_bg_alt')}; border: 1px solid {R('panel_border')}; border-radius: 3px; padding: 4px 8px; font-family: monospace; font-size: 11px; color: {R('text')}; word-break: break-all;">
                    <b>{html.escape(evidence_heading)}</b>
                    {evidence_block}
                </div>
                {limitations_html}
            </div>
            """
            cards.append(card)

        if coverage:
            coverage_blocks = [
                self._format_coverage_block(f, card_index,
                                              card_index in expanded,
                                              preview_limit=preview_limit)
                for card_index, f in coverage
            ]
            cards.append(f"""
            <div style="font-weight: bold; font-size: 13px; margin: 12px 0 8px; color: {R('text_alt')};">=== COVERAGE &amp; LIMITATIONS ({len(coverage)} noted) ===</div>
            <div style="font-family: sans-serif; font-size: 11px; color: {R('muted')}; margin-bottom: 8px; line-height: 1.4;">
                A browser listed as not detected was simply not found on this system. A missing profile
                directory is not automatically a vulnerability. An unsupported browser was not scanned,
                which is not the same as a failed scan. Unchecked sources are coverage gaps — never
                confirmed exposures.
            </div>
            {"".join(coverage_blocks)}
            """)

        cards.append('</div>')
        return "\n".join(cards)

    def _format_coverage_block(self, f, card_index, is_expanded,
                               preview_limit=None):
        """Render one coverage/limitation finding without duplicating data.

        Description lines render directly. The evidence box is skipped when
        every evidence entry already appears in the description (e.g. source
        paths, limitation messages), since re-rendering it would duplicate
        the same content. Long description lists are previewed with the
        shared Show-all/Show-less mechanism.
        """
        ftype = (getattr(f, "finding_type", "") or "")
        if ftype == "Scan Coverage":
            intro = ("What was checked during the scan. "
                     "Items listed as searched but not detected mean no matching "
                     "footprint was found — not proof that no footprint exists.")
        elif ftype == "Unavailable Sources":
            intro = ("Sources that could not be checked. These are gaps in "
                     "coverage, not confirmed exposures.")
        elif ftype == "Scan Warnings":
            intro = ("Non-fatal notices from the scan. The scan still completed.")
        else:
            intro = ("A scan limitation reduced coverage. This describes what "
                     "could not be checked, not a confirmed exposure.")
        desc_lines = [p.strip() for p in str(f.description or "").split("|")]
        desc_lines = [p for p in desc_lines if p]
        items = collect_finding_evidence_items(f.evidence)
        description_text = str(f.description or "")
        duplicates = bool(items) and all(item in description_text for item in items)

        if duplicates:
            if len(desc_lines) > COVERAGE_DESCRIPTION_PREVIEW_LIMIT and not is_expanded:
                shown = desc_lines[:COVERAGE_DESCRIPTION_PREVIEW_LIMIT]
                more = len(desc_lines) - len(shown)
                toggle = (
                    f'<div style="font-size: 11px; color: {R('faint_meta')}; font-style: italic; margin-top: 4px;">'
                    f'+{more} more — '
                    f'<a href="#ev-{card_index}-show" style="color: {R('link')};">Show all</a></div>'
                )
            else:
                shown = desc_lines
                toggle = ""
                if len(desc_lines) > COVERAGE_DESCRIPTION_PREVIEW_LIMIT and is_expanded:
                    toggle = (
                        f'<div style="font-size: 11px; margin-top: 4px;">'
                        f'<a href="#ev-{card_index}-hide" style="color: {R('link')};">Show less</a></div>'
                    )
            desc_html = "".join(
                f'<div style="font-size: 12px; color: {R('text')}; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(p)}</div>'
                for p in shown
            ) + toggle
            evidence_html = ""
        else:
            desc_html = "".join(
                f'<div style="font-size: 12px; color: {R('text')}; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(p)}</div>'
                for p in desc_lines
            )
            evidence_html = f"""
                <div style="background-color: {R('panel_bg_alt')}; border: 1px solid {R('panel_border')}; border-radius: 3px; padding: 4px 8px; margin-top: 5px; font-size: 11px; color: {R('text')}; word-break: break-all;">
                    {format_finding_evidence_html(f.evidence, preview_limit=preview_limit, expanded=is_expanded, card_index=card_index)}
                </div>"""

        return f"""
            <div style="border: 1px solid {R('panel_border')}; border-radius: 4px; background-color: {R('card_bg')}; padding: 8px 10px; margin-bottom: 8px;">
                <div style="font-size: 12px; font-weight: bold; color: {R('text')}; margin-bottom: 3px;">
                    {html.escape(f.title)}
                </div>
                <div style="font-size: 11px; color: {R('muted')}; font-style: italic; margin-bottom: 5px;">
                    {html.escape(intro)}
                </div>
                {desc_html}{evidence_html}
            </div>
                """

    def format_system_evidence_html(self, footprint_data, view_key=None,
                                      collapsed=frozenset(), expanded_records=frozenset()):
        """Formats System Footprint collected evidence with structured sections and word-wrap.

        Optional view_key enables group collapse controls and collapsible
        record details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        system_info = []
        installed_apps = []
        processes = []
        startups = []

        for fd in footprint_data:
            if fd.subcategory == "Installed Applications":
                installed_apps.append(fd)
            elif fd.subcategory == "Running Processes":
                processes.append(fd)
            elif fd.subcategory == "Startup Applications":
                startups.append(fd)
            else:
                system_info.append(fd)

        def _records(items, group):
            return "\n".join(
                format_evidence_record_html(
                    fd.subcategory, fd.value, fd.source,
                    view_key=view_key,
                    record_key=f"{group}:{i}",
                    expanded=f"{group}:{i}" in expanded_records,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed,
            )
            lines.append(header)
            if show_body:
                lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>',
            f'<div style="font-weight: bold; font-size: 12px; color: {R("header_accent")}; margin-bottom: 4px;">System Footprint:</div>'
        ]

        if system_info:
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in system_info:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px;"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: {R('faint')}; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if startups:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">Startup Applications ({len(startups)} detected):</div>', "startups", startups)

        if installed_apps:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">Installed Applications ({len(installed_apps)} detected):</div>', "installed_apps", installed_apps)

        if processes:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">Running Processes ({len(processes)} detected):</div>', "processes", processes)

        lines.append('</div>')
        return "\n".join(lines)

    def format_browser_evidence_html(self, footprint_data, view_key=None,
                                       collapsed=frozenset(), expanded_records=frozenset()):
        """Formats Browser Footprint collected evidence with structured sections and word-wrap.

        Optional view_key enables group collapse controls and collapsible
        extension details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        browsers = []
        extensions = []
        coverage = []

        for fd in footprint_data:
            if fd.subcategory == "Detected Browser":
                browsers.append(fd)
            elif fd.subcategory == "Extension":
                extensions.append(fd)
            else:
                coverage.append(fd)

        def _records(items, group):
            return "\n".join(
                format_evidence_record_html(
                    fd.subcategory, fd.value, fd.source,
                    view_key=view_key,
                    record_key=f"{group}:{i}",
                    expanded=f"{group}:{i}" in expanded_records,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed,
            )
            lines.append(header)
            if show_body:
                lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>'
        ]

        if browsers:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">Detected Browsers ({len(browsers)}):</div>', "browsers", browsers)

        if extensions:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">Installed Extensions ({len(extensions)}):</div>', "extensions", extensions)

        if coverage:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {R("header_accent")}; margin-bottom: 4px;">Scan Coverage Notes:</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for c in coverage:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px;">{html.escape(str(c.value))}</div>')
            lines.append('</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_file_evidence_html(self, footprint_data, view_key=None,
                                    collapsed=frozenset(), expanded_records=frozenset()):
        """Formats File & Metadata collected evidence.

        Optional view_key enables group collapse controls and collapsible
        record details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        file_details = []
        meta_entries = []
        sensitive_entries = []

        for fd in footprint_data:
            if fd.subcategory in ("File Information", "File Path", "File Timestamps"):
                file_details.append(fd)
            elif fd.subcategory == "Embedded Metadata":
                meta_entries.append(fd)
            elif fd.subcategory == "Potentially Sensitive":
                sensitive_entries.append(fd)

        sensitive_box = f'<div style="background-color: {R("sensitive_bg")}; border: 1px solid {R("sensitive_border")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">'

        def _records(items, group, marker="•", headline_color=None):
            return "\n".join(
                format_evidence_record_html(
                    fd.subcategory, fd.value, fd.source,
                    view_key=view_key,
                    record_key=f"{group}:{i}",
                    expanded=f"{group}:{i}" in expanded_records,
                    marker=marker,
                    headline_color=headline_color,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items, box_open=None, marker="•",
                   headline_color=None):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed,
            )
            lines.append(header)
            if show_body:
                lines.append(box_open or f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group, marker=marker,
                                      headline_color=headline_color))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FILE & METADATA FOOTPRINT ===</div>'
        ]

        if file_details:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {R("header_accent")}; margin-bottom: 4px;">[File Details]</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for item in file_details:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;">• {html.escape(str(item))}</div>')
            lines.append('</div>')

        if sensitive_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('danger_header')}; margin-bottom: 4px;">[Potentially Sensitive Metadata ({len(sensitive_entries)} items)]</div>', "sensitive", sensitive_entries, box_open=sensitive_box, marker="⚠️", headline_color=f"{R('sensitive_text')}")
        else:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {R("subtle_alt")}; margin-bottom: 4px;">[Potentially Sensitive Metadata]</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {R("subtle")};">No potentially sensitive metadata detected in this file.</div>')

        if meta_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {R('header_accent')}; margin-bottom: 4px;">[Extracted Metadata ({len(meta_entries)} fields)]</div>', "meta", meta_entries)

        lines.append('</div>')
        return "\n".join(lines)

    def format_full_scan_evidence_html(self, result, query="", module="All",
                                         view_key=None, collapsed=frozenset(),
                                         expanded_records=frozenset()):
        """Formats Full Scan collected evidence by reusing per-module renderers.

        An optional search query and module filter narrow the rendered
        records; the underlying result data is never modified. Counts in
        section headers reflect the filtered view, with a match note stating
        how many of the total records are shown. Per-module section labels
        come from the delegated renderers, so no duplicate headers are added
        here. Optional view_key enables group collapse controls and
        collapsible record details.
        """
        footprint_data = result.footprint_data or []
        total_records = len(footprint_data)
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        visible = filter_footprint(footprint_data, query=query, module=module)
        system = [fd for fd in visible if fd.category == "System"]
        browser = [fd for fd in visible if fd.category == "Browser"]
        file_items = [fd for fd in visible if fd.category == "File & Metadata"]
        other = [fd for fd in visible if fd.category not in ("System", "Browser", "File & Metadata")]

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FULL SCAN EVIDENCE ===</div>'
        ]

        if query or (module and module != "All"):
            lines.append(
                f'<div style="font-size: 12px; color: {R('muted')}; margin-bottom: 8px;">'
                f'Filter matched <b>{len(visible)}</b> of <b>{total_records}</b> records.</div>'
            )

        if system:
            lines.append(self.format_system_evidence_html(
                system, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records))

        if browser:
            lines.append(self.format_browser_evidence_html(
                browser, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records))

        if file_items:
            lines.append(self.format_file_evidence_html(
                file_items, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records))
        elif "no file selected" in (result.message or "").lower():
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {R("subtle")};">File Metadata was skipped because no file was selected. Select a file and run Full Scan again to include it.</div>')

        if other:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {R("header_accent")}; margin-bottom: 4px;">Additional Evidence:</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in other:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: {R('faint')}; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if not visible and footprint_data:
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {R("subtle")};">No records match the current filter. Clear the search or choose a different module to see more evidence.</div>')
        elif not footprint_data:
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {R("subtle")};">No collected evidence was returned by the included modules.</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_public_evidence_html(self, footprint_data, findings):
        """Formats Public Lookup evidence while preserving text compatibility."""
        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">'
        ]

        if footprint_data:
            lines.append('<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in footprint_data:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 4px; word-break: break-all;">Source: {html.escape(fd.source)}<br>Value: {html.escape(str(fd.value))}</div>')
            lines.append('</div>')

        if findings:
            lines.append(f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FINDINGS ===</div>')
            lines.append(f'<div style="background-color: {R("panel_bg")}; border: 1px solid {R("panel_border_alt")}; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for f in findings:
                ev_str = ", ".join(f.evidence) if isinstance(f.evidence, list) else str(f.evidence)
                lines.append(f'<div style="font-size: 12px; margin-bottom: 6px;">[{html.escape(f.severity)}] {html.escape(f.title)}<br>Description: {html.escape(f.description)}<br>Evidence: {html.escape(ev_str)}</div>')
            lines.append('</div>')

        lines.append('</div>')
        return "\n".join(lines)

    # --------------------------------------------------------
    # SCAN COMPLETION AND ERROR DISPATCH
    # --------------------------------------------------------

    def on_scan_complete(self, result):
        is_sys = (result.scan_type == "System")
        is_file = (result.scan_type == "File & Metadata")
        is_browser = (result.scan_type == "Browser")
        is_full = (result.scan_type == "Full Scan")
        if is_sys:
            view_key = "sys"
        elif is_browser:
            view_key = "browser"
        elif is_file:
            view_key = "file"
        elif is_full:
            view_key = "full"
        else:
            view_key = "public"

        # Track the latest result per view for evidence expand/collapse and
        # evidence filtering. A new result object resets that view's expanded
        # set; re-rendering the same object (e.g. after a toggle) preserves it.
        if self._last_results.get(view_key) is not result:
            self._expanded_cards[view_key] = set()
            self._collapsed_evidence[view_key] = set()
            self._expanded_evidence_records[view_key] = set()
        self._last_results[view_key] = result

        status_text = f"Status: {result.status} | Message: {result.message}"
        findings_count = len(result.findings)
        evidence_count = len(result.footprint_data)

        # Generate shared formatted findings HTML. evidence_count is the
        # number of FootprintData records (one per Collected Evidence entry);
        # finding evidence entries are rendered inside cards but never added
        # to this count, so shared data is not counted twice. The summary is
        # a read-only display model built from result data for Full Scan.
        findings_html = self.format_findings_html(
            result.findings,
            evidence_count=evidence_count,
            scan_status=result.status,
            expanded=self._expanded_cards.get(view_key, set()),
            summary=summarize_full_scan(result) if is_full else None,
        )

        if is_sys:
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(status_text)
            self.sys_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.sys_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.sys_findings_area.setHtml(findings_html)
            self._render_view_evidence("sys")

            # Switch to Findings if any exist, otherwise Evidence
            self.sys_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        elif is_browser:
            self.browser_scan_btn.setEnabled(True)
            self.browser_status_label.setText(status_text)
            self.browser_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.browser_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.browser_findings_area.setHtml(findings_html)
            self._render_view_evidence("browser")

            self.browser_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        elif is_file:
            self.file_select_btn.setEnabled(True)
            self.file_analyze_btn.setEnabled(True)
            self.file_status_label.setText(status_text)
            self.file_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.file_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.file_findings_area.setHtml(findings_html)
            self._render_view_evidence("file")

            self.file_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        elif is_full:
            self.full_scan_btn.setEnabled(True)
            self.full_scan_select_btn.setEnabled(True)
            self.full_scan_clear_btn.setEnabled(self.full_scan_file_path is not None)
            self.full_scan_status_label.setText(status_text)
            self.full_scan_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.full_scan_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.full_scan_findings_area.setHtml(findings_html)
            self.full_scan_results_area.setHtml(self.format_full_scan_evidence_html(
                result,
                query=self.full_evidence_search.text(),
                module=self._full_evidence_module_filter(),
            ))

            # Switch to Findings if any exist, otherwise Evidence
            self.full_scan_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        else:
            self.scan_btn.setEnabled(True)
            self.status_label.setText(status_text)
            self.public_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.public_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.public_findings_area.setHtml(findings_html)
            self.results_area.setHtml(self.format_public_evidence_html(result.footprint_data, result.findings))

            self.public_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        self._refresh_dashboard(result)
        # One place turns a finished scan into an assessment, a stored record,
        # and an action plan; the pages, the dashboard strip, and the exports
        # all read that same result.
        self._record_scan_assessment(result)

    def on_scan_error(self, err_msg):
        if hasattr(self, 'scan_btn'):
            self.scan_btn.setEnabled(True)
            self.status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'sys_scan_btn'):
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'file_select_btn'):
            self.file_select_btn.setEnabled(True)
        if hasattr(self, 'file_analyze_btn'):
            self.file_analyze_btn.setEnabled(True)
        if hasattr(self, 'file_status_label'):
            self.file_status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'browser_scan_btn'):
            self.browser_scan_btn.setEnabled(True)
        if hasattr(self, 'browser_status_label'):
            self.browser_status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'full_scan_btn'):
            self.full_scan_btn.setEnabled(True)
        if hasattr(self, 'full_scan_select_btn'):
            self.full_scan_select_btn.setEnabled(True)
        if hasattr(self, 'full_scan_clear_btn'):
            self.full_scan_clear_btn.setEnabled(bool(getattr(self, 'full_scan_file_path', None)))
        if hasattr(self, 'full_scan_status_label'):
            self.full_scan_status_label.setText(f"Error: {err_msg}")

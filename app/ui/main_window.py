import os
import html
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QTextEdit, QTextBrowser, QStackedWidget, QListWidget, QTabWidget, QFileDialog
)
from PySide6.QtCore import Qt, QTimer
from app.ui.workers import ScanWorker


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

MODULE_LABELS = (
    ("System", "System"),
    ("Browser", "Browser"),
    ("File & Metadata", "File"),
)


def summarize_full_scan(result):
    """Build a read-only display summary for a Full Scan result.

    Derives per-module states from the result message, limitation finding
    titles, and footprint categories present. Never invents statistics:
    every row traces back to result data.
    """
    findings = list(result.findings or [])
    footprint = list(result.footprint_data or [])
    message = (result.message or "").lower()

    def _has_limitation(*keywords):
        return any(
            (getattr(f, "finding_type", "") or "") == "Scan Limitation"
            and any(k.lower() in (f.title or "").lower() for k in keywords)
            for f in findings
        )

    modules = []
    categories = {getattr(fd, "category", "") for fd in footprint}
    for category, label in MODULE_LABELS:
        if category == "File & Metadata" and "no file selected" in message:
            modules.append({
                "name": label,
                "state": "skipped",
                "note": "Skipped — no file was selected",
            })
        elif _has_limitation(label, category):
            if label == "Browser" and (
                "unavailable" in message or "not available" in message
            ):
                modules.append({
                    "name": label,
                    "state": "limited",
                    "note": "Unavailable on this platform — not scanned",
                })
            else:
                modules.append({
                    "name": label,
                    "state": "limited",
                    "note": "Had limitations — see limitation notes",
                })
        elif category in categories:
            modules.append({"name": label, "state": "completed", "note": "Completed"})
        else:
            modules.append({"name": label, "state": "unknown", "note": "No data"})

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
        "evidence_records": len(footprint),
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
        f'<div style="font-size: 12px; color: #586069; margin-bottom: 8px;">'
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
        f' <span style="color: #888; font-size: 11px;">[Source: {html.escape(str(source))}]</span>'
        if source else ""
    )
    if " — " in headline and not headline_color:
        name_part, rest_part = headline.split(" — ", 1)
        headline_open = (
            f'<b>{html.escape(name_part)}</b>'
            f'<span style="color: #586069;"> — {html.escape(rest_part)}</span>'
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
        f'<span style="color: #0366d6;">{html.escape(marker)}</span> {headline_open}{source_html}</div>'
    ]
    for detail in visible:
        lines.append(_detail_div(detail, "#586069"))
    if hidden:
        if expanded:
            for detail in hidden:
                lines.append(_detail_div(detail, "#24292e"))
            if view_key is not None and record_key is not None:
                lines.append(
                    f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                    f'<a href="#evd-{view_key}-{record_key}-hide" style="color: #0366d6;">'
                    f'Hide details</a></div>'
                )
        elif view_key is not None and record_key is not None:
            lines.append(
                f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                f'<a href="#evd-{view_key}-{record_key}-show" style="color: #0366d6;">'
                f'Details</a></div>'
            )
        else:
            for detail in hidden:
                lines.append(
                    f'<div style="font-size: 11px; color: #586069; margin: 0 0 2px 14px; '
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
                f'<a href="#evd-{view_key}-g-{group_key}-show" style="color: #0366d6; '
                f'font-size: 11px; font-weight: normal;">Expand ({count} records hidden)</a>',
                False,
            )
        return (
            f'{title_html} '
            f'<a href="#evd-{view_key}-g-{group_key}-hide" style="color: #0366d6; '
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
        return '<div style="font-size: 11px; color: #6a737d; font-style: italic;">No evidence recorded.</div>'

    if expanded or len(items) <= preview_limit:
        shown = items
    else:
        shown = items[:preview_limit]
    lines = []
    for item in shown:
        lines.append(
            f'<div style="font-size: 11px; margin-bottom: 2px; word-break: break-all;">'
            f'<span style="color: #0366d6;">•</span> {html.escape(item)}</div>'
        )
    remaining = len(items) - len(shown)
    if card_index is not None and (remaining > 0 or expanded):
        if expanded:
            lines.append(
                f'<div style="font-size: 11px; margin-top: 4px;">'
                f'<a href="#ev-{card_index}-hide" style="color: #0366d6;">Show less</a>'
                f'<span style="color: #6a737d;"> · full list also in Collected Evidence.</span></div>'
            )
        else:
            lines.append(
                f'<div style="font-size: 11px; color: #6a737d; font-style: italic; margin-top: 4px;">'
                f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
                f'<a href="#ev-{card_index}-show" style="color: #0366d6;">Show all</a> · '
                f'see Collected Evidence for the complete records.</div>'
            )
    elif remaining > 0:
        lines.append(
            f'<div style="font-size: 11px; color: #6a737d; font-style: italic; margin-top: 4px;">'
            f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
            f'see Collected Evidence for the complete records.</div>'
        )
    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Footprint Analyzer")
        self.resize(850, 650)

        self.worker = None
        self.selected_file_path = None
        self.full_scan_file_path = None
        # Display-only render state: last result per findings view plus the
        # set of expanded evidence-card indices per view. Never affects scan
        # semantics; cleared whenever a new result arrives for a view.
        self._last_results = {}
        self._expanded_cards = {}
        self._evidence_filter_timer = None
        self._pending_evidence_view = None
        # Per-view evidence-explorer state (collapsed groups and expanded
        # records), reset on new results or filter changes. Presentation only.
        self._collapsed_evidence = {}
        self._expanded_evidence_records = {}

        # Main widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        # Sidebar navigation
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(150)
        self.sidebar.addItem("Home")
        self.sidebar.addItem("My Footprint")
        self.sidebar.addItem("Public Lookup")
        self.sidebar.addItem("Settings")
        self.sidebar.currentRowChanged.connect(self.change_page)
        main_layout.addWidget(self.sidebar)

        # Stacked widget for pages
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages)

        # Initialize pages
        self.init_home_page()
        self.init_my_footprint_page()
        self.init_public_lookup_page()
        self.init_settings_page()

        self.sidebar.setCurrentRow(2)  # Default to Public Lookup

    def init_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Welcome to Digital Footprint Analyzer</h2>"))
        layout.addWidget(QLabel("A privacy and security awareness application to analyze local traces and public digital exposure."))
        layout.addStretch()
        self.pages.addWidget(page)

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
        self.selected_file_label.setStyleSheet("color: #888;")
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
        self.full_scan_file_label.setStyleSheet("color: #888;")
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

    def init_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Settings</h2>"))
        layout.addWidget(QLabel("Application settings and configuration."))
        layout.addStretch()
        self.pages.addWidget(page)

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

        self.worker = ScanWorker("System", "")
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

        self.worker = ScanWorker(scan_type, target)
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
            self.selected_file_label.setStyleSheet("color: #000; font-weight: bold;")
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
            self.full_scan_file_label.setStyleSheet("color: #000; font-weight: bold;")
            self.full_scan_clear_btn.setEnabled(True)
            self.full_scan_status_label.setText("File selected. Click 'Run Full Scan' to include it; otherwise System and Browser scans run without File Metadata.")

    def clear_full_scan_file(self):
        self.full_scan_file_path = None
        self.full_scan_file_label.setText("No file selected")
        self.full_scan_file_label.setStyleSheet("color: #888;")
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
            body += ('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; '
                     'border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; '
                     'color: #666;">No records match the current filter. Clear the search '
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
                               expanded=frozenset(), summary=None):
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
                "COMPLETED": ("#22863a", "#e6f4ea", "#b7e0c3"),
                "PARTIAL": ("#b04300", "#fff5e6", "#f0c48c"),
                "ERROR": ("#cb2431", "#ffeef0", "#f5b5ba"),
            }
            status_key = str(scan_status).strip().upper()
            text_color, bg_color, border_color = status_styles.get(
                status_key, ("#586069", "#f6f8fa", "#e1e4e8")
            )
            guidance = SCAN_STATUS_GUIDANCE.get(status_key, "")
            guidance_html = (
                f'<span style="color: #586069;"> — {html.escape(guidance)}</span>'
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
                "background-color: #e1e4e8; color: #24292e;"
                if count else "background-color: #f6f8fa; color: #959da5;"
            )
            severity_chips.append(
                f'<span style="{chip_style} font-weight: bold; padding: 2px 6px; '
                f'border-radius: 3px; font-size: 11px; margin-right: 4px;">'
                f'{html.escape(sev)}: {count}</span>'
            )
        severity_row = f"""
        <div style="font-family: sans-serif; margin-bottom: 8px; font-size: 12px; color: #333;">
            <b>By severity:</b> {"&nbsp;&nbsp;".join(severity_chips)}
        </div>
        """

        # Per-module outcome rows supplied by the display summary, if any.
        module_rows = ""
        if summary and summary.get("modules"):
            state_styles = {
                "completed": ("#22863a", "✓"),
                "limited": ("#b04300", "⚠"),
                "failed": ("#cb2431", "✕"),
                "skipped": ("#586069", "⊘"),
                "unknown": ("#959da5", "?"),
            }
            row_lines = []
            for mod in summary["modules"]:
                color, mark = state_styles.get(
                    mod.get("state", "unknown"), ("#959da5", "?")
                )
                row_lines.append(
                    f'<div style="font-size: 12px; margin-bottom: 2px; color: #333;">'
                    f'<span style="color: {color}; font-weight: bold;">{mark}</span> '
                    f'<b>{html.escape(mod.get("name", "?"))}:</b> '
                    f'{html.escape(mod.get("note", ""))}</div>'
                )
            module_rows = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: #fbfcfd; border: 1px solid #e1e4e8; border-radius: 6px;">
            <div style="font-size: 12px; font-weight: bold; color: #24292e; margin-bottom: 4px;">Modules:</div>
            {"".join(row_lines)}
        </div>
        """

        # Limitations are scan-coverage notes, never privacy exposures.
        limitation_note = ""
        if limitation_count > 0:
            limitation_note = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: #f6f8fa; border: 1px dotted #b1b7c0; border-radius: 6px; font-size: 11px; color: #586069;">
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
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: #f8f9fa; border: 1px solid #e1e4e8; border-radius: 6px; font-size: 12px; color: #333; line-height: 2;">
            <b>SCAN SUMMARY:</b>
            <span style="margin-left: 8px;"><b>Total Findings:</b> <span style="background-color: #e1e4e8; color: #24292e; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{total_findings}</span></span>
            <span style="margin-left: 8px;"><b>Concerns:</b> <span style="background-color: #ffeef0; color: #cb2431; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{concerns_count}</span></span>
            <span style="margin-left: 8px;"><b>Observations:</b> <span style="background-color: #f1f8ff; color: #0366d6; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{observations_count}</span></span>
            <span style="margin-left: 8px;"><b>Evidence Items:</b> <span style="background-color: #f6f8fa; color: #444d56; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{evidence_count}</span></span>
        </div>
        {limitation_note}
        """

        if not findings:
            failure_note = ""
            if scan_status and str(scan_status).strip().upper() == "ERROR":
                failure_note = """
                <div style="padding: 12px; border: 1px solid #f5b5ba; border-radius: 6px; background-color: #ffeef0; color: #86181d; margin-top: 4px; font-size: 12px;">
                    <b>The scan did not complete.</b> No findings could be produced because the
                    scan itself failed — this is not a clean bill of health. Check the status
                    message for details and try running the scan again.
                </div>
                """
            return f"""
            <div style="font-family: sans-serif; padding: 4px;">
                {summary_html}
                {failure_note}
                <div style="padding: 16px; border: 1px dashed #7f848e; border-radius: 6px; background-color: #2b2b2b; color: #abb2bf; margin-top: 4px;">
                    <h3 style="margin-top: 0; color: #98c379; font-size: 14px;">No findings were generated for this scan.</h3>
                    <p style="margin-bottom: 0; font-size: 12px; color: #7f848e; line-height: 1.4;">
                        All evaluated rule conditions were negative for positive exposure evidence.<br>
                        <i>Note: An absence of findings indicates that no supported rule conditions were met, but does not guarantee the system or identifier is free of all privacy or security exposure.</i>
                    </p>
                </div>
            </div>
            """

        cards = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            summary_html,
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: #333;">=== FINDINGS ({total_findings} detected) ===</div>'
        ]

        for card_index, f in regular:
            cat = getattr(f, "category", "Observation") or "Observation"
            sev = f.severity or "Info"
            rule_id = getattr(f, "rule_id", None)
            limitations = getattr(f, "limitations", None)

            # Restrained, distinct badge and border color palette
            is_concern = (cat == "Concern")
            if is_concern:
                cat_badge_bg = "#d73a49" if sev in ("High", "Critical") else "#e36209"
                card_border = "#d73a49" if sev in ("High", "Critical") else "#e36209"
                card_bg = "#fff8f8" if sev in ("High", "Critical") else "#fffbf5"
                title_color = "#cb2431" if sev in ("High", "Critical") else "#b04300"
            else:
                cat_badge_bg = "#0366d6"
                card_border = "#0366d6"
                card_bg = "#fbfcfd"
                title_color = "#0366d6"

            sev_colors = {
                "Critical": "#d73a49",
                "High": "#d73a49",
                "Medium": "#e36209",
                "Low": "#005cc5",
                "Info": "#0366d6"
            }
            sev_bg = sev_colors.get(sev, "#0366d6")

            sev_guidance = SEVERITY_GUIDANCE.get(sev, f"{sev} · for awareness")
            cat_guidance = ("Potential concern" if cat == "Concern"
                            else "Informational observation")
            evidence_count_for_card = len(collect_finding_evidence_items(f.evidence))
            evidence_block = format_finding_evidence_html(
                f.evidence, expanded=(card_index in expanded), card_index=card_index
            )
            evidence_heading = (
                f"Evidence ({evidence_count_for_card} "
                f"entr{'y' if evidence_count_for_card == 1 else 'ies'}):"
                if evidence_count_for_card
                else "Evidence:"
            )

            rule_html = f'<span style="font-size: 11px; color: #6a737d; font-family: monospace;">Rule: {html.escape(rule_id)}</span>' if rule_id else ""
            limitations_html = (
                f'<div style="font-size: 11px; color: #586069; font-style: italic; margin-top: 5px; padding-top: 4px; border-top: 1px dotted #e1e4e8;">'
                f'<b>Scope Limitation:</b> {html.escape(limitations)}</div>'
            ) if limitations else ""

            card = f"""
            <div style="border: 1px solid #e1e4e8; border-left: 4px solid {card_border}; border-radius: 4px; background-color: {card_bg}; padding: 6px 10px; margin-bottom: 8px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 4px;">
                    <tr>
                        <td align="left">
                            <span style="background-color: {cat_badge_bg}; color: #ffffff; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 3px;">{html.escape(cat.upper())}</span>
                            <span style="background-color: {sev_bg}; color: #ffffff; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 3px; margin-left: 4px;">{html.escape(sev.upper())}</span>
                        </td>
                        <td align="right">
                            {rule_html}
                        </td>
                    </tr>
                </table>
                <div style="font-size: 13px; font-weight: bold; color: {title_color}; margin-bottom: 3px;">
                    {html.escape(f.title)}
                </div>
                <div style="font-size: 11px; color: #586069; margin-bottom: 4px;">
                    {html.escape(sev_guidance)} · {html.escape(cat_guidance)}
                </div>
                <div style="font-size: 12px; color: #24292e; line-height: 1.4; margin-bottom: 4px;">
                    {html.escape(f.description)}
                </div>
                <div style="background-color: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 3px; padding: 4px 8px; font-family: monospace; font-size: 11px; color: #24292e; word-break: break-all;">
                    <b>{html.escape(evidence_heading)}</b>
                    {evidence_block}
                </div>
                {limitations_html}
            </div>
            """
            cards.append(card)

        if coverage:
            coverage_blocks = [
                self._format_coverage_block(f, card_index, card_index in expanded)
                for card_index, f in coverage
            ]
            cards.append(f"""
            <div style="font-weight: bold; font-size: 13px; margin: 12px 0 8px; color: #333;">=== COVERAGE &amp; LIMITATIONS ({len(coverage)} noted) ===</div>
            <div style="font-family: sans-serif; font-size: 11px; color: #586069; margin-bottom: 8px; line-height: 1.4;">
                A browser listed as not detected was simply not found on this system. A missing profile
                directory is not automatically a vulnerability. An unsupported browser was not scanned,
                which is not the same as a failed scan. Unchecked sources are coverage gaps — never
                confirmed exposures.
            </div>
            {"".join(coverage_blocks)}
            """)

        cards.append('</div>')
        return "\n".join(cards)

    def _format_coverage_block(self, f, card_index, is_expanded):
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
                    f'<div style="font-size: 11px; color: #6a737d; font-style: italic; margin-top: 4px;">'
                    f'+{more} more — '
                    f'<a href="#ev-{card_index}-show" style="color: #0366d6;">Show all</a></div>'
                )
            else:
                shown = desc_lines
                toggle = ""
                if len(desc_lines) > COVERAGE_DESCRIPTION_PREVIEW_LIMIT and is_expanded:
                    toggle = (
                        f'<div style="font-size: 11px; margin-top: 4px;">'
                        f'<a href="#ev-{card_index}-hide" style="color: #0366d6;">Show less</a></div>'
                    )
            desc_html = "".join(
                f'<div style="font-size: 12px; color: #24292e; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(p)}</div>'
                for p in shown
            ) + toggle
            evidence_html = ""
        else:
            desc_html = "".join(
                f'<div style="font-size: 12px; color: #24292e; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(p)}</div>'
                for p in desc_lines
            )
            evidence_html = f"""
                <div style="background-color: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 3px; padding: 4px 8px; margin-top: 5px; font-size: 11px; color: #24292e; word-break: break-all;">
                    {format_finding_evidence_html(f.evidence, expanded=is_expanded, card_index=card_index)}
                </div>"""

        return f"""
            <div style="border: 1px solid #e1e4e8; border-radius: 4px; background-color: #fbfcfd; padding: 8px 10px; margin-bottom: 8px;">
                <div style="font-size: 12px; font-weight: bold; color: #24292e; margin-bottom: 3px;">
                    {html.escape(f.title)}
                </div>
                <div style="font-size: 11px; color: #586069; font-style: italic; margin-bottom: 5px;">
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
                lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>',
            '<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">System Footprint:</div>'
        ]

        if system_info:
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in system_info:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px;"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: #888; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if startups:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Startup Applications ({len(startups)} detected):</div>', "startups", startups)

        if installed_apps:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Installed Applications ({len(installed_apps)} detected):</div>', "installed_apps", installed_apps)

        if processes:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Running Processes ({len(processes)} detected):</div>', "processes", processes)

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
                lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>'
        ]

        if browsers:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Detected Browsers ({len(browsers)}):</div>', "browsers", browsers)

        if extensions:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Installed Extensions ({len(extensions)}):</div>', "extensions", extensions)

        if coverage:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Scan Coverage Notes:</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
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

        sensitive_box = '<div style="background-color: #fff8f8; border: 1px solid #f5c6cb; border-radius: 4px; padding: 8px; margin-bottom: 10px;">'

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
                lines.append(box_open or '<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
                lines.append(_records(items, group, marker=marker,
                                      headline_color=headline_color))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FILE & METADATA FOOTPRINT ===</div>'
        ]

        if file_details:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">[File Details]</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for item in file_details:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;">• {html.escape(str(item))}</div>')
            lines.append('</div>')

        if sensitive_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #d9534f; margin-bottom: 4px;">[Potentially Sensitive Metadata ({len(sensitive_entries)} items)]</div>', "sensitive", sensitive_entries, box_open=sensitive_box, marker="⚠️", headline_color="#721c24")
        else:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #555; margin-bottom: 4px;">[Potentially Sensitive Metadata]</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: #666;">No potentially sensitive metadata detected in this file.</div>')

        if meta_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">[Extracted Metadata ({len(meta_entries)} fields)]</div>', "meta", meta_entries)

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
                f'<div style="font-size: 12px; color: #586069; margin-bottom: 8px;">'
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
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: #666;">File Metadata was skipped because no file was selected. Select a file and run Full Scan again to include it.</div>')

        if other:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Additional Evidence:</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in other:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: #888; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if not visible and footprint_data:
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: #666;">No records match the current filter. Clear the search or choose a different module to see more evidence.</div>')
        elif not footprint_data:
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: #666;">No collected evidence was returned by the included modules.</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_public_evidence_html(self, footprint_data, findings):
        """Formats Public Lookup evidence while preserving text compatibility."""
        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">'
        ]

        if footprint_data:
            lines.append('<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for fd in footprint_data:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 4px; word-break: break-all;">Source: {html.escape(fd.source)}<br>Value: {html.escape(str(fd.value))}</div>')
            lines.append('</div>')

        if findings:
            lines.append(f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FINDINGS ===</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
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

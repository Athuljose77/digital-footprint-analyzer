import os
import html
import platform
import getpass
import sys
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QTextEdit, QTextBrowser, QStackedWidget, QListWidget, QTabWidget, QFileDialog,
    QScrollArea, QFrame, QGridLayout, QGroupBox, QRadioButton, QButtonGroup, QCheckBox
)
from PySide6.QtCore import Qt, QTimer, QSettings
from PySide6.QtGui import QPalette
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


def get_theme_palette(is_dark: bool = False) -> dict:
    """Return color and style palette for light or dark mode."""
    if is_dark:
        return {
            "is_dark": True,
            "page_bg": "#0f172a",
            "text_primary": "#f8fafc",
            "text_secondary": "#94a3b8",
            "text_muted": "#64748b",
            "box_bg": "#1e293b",
            "box_border": "#334155",
            "box_text": "#f1f5f9",
            "header_color": "#60a5fa",
            "link_color": "#38bdf8",
            "bullet_color": "#60a5fa",
            "detail_color": "#94a3b8",
            "detail_expanded_color": "#f8fafc",
            "sensitive_box_bg": "#2d1519",
            "sensitive_box_border": "#7f1d1d",
            "sensitive_box_text": "#fca5a5",
            "sensitive_headline_color": "#f87171",
            "card_bg": "#1e293b",
            "card_border": "#334155",
            "card_text": "#f1f5f9",
            "summary_bg": "#1e293b",
            "summary_border": "#334155",
            "summary_text": "#f8fafc",
            "note_bg": "#1e293b",
            "note_border": "#475569",
            "note_text": "#94a3b8",
            "selection_bg": "#2563eb",
            "selection_text": "#ffffff",
        }
    else:
        return {
            "is_dark": False,
            "page_bg": "#ffffff",
            "text_primary": "#0f172a",
            "text_secondary": "#586069",
            "text_muted": "#888",
            "box_bg": "#f8f9fa",
            "box_border": "#e9ecef",
            "box_text": "#24292e",
            "header_color": "#1e3799",
            "link_color": "#0366d6",
            "bullet_color": "#0366d6",
            "detail_color": "#586069",
            "detail_expanded_color": "#24292e",
            "sensitive_box_bg": "#fff8f8",
            "sensitive_box_border": "#f5c6cb",
            "sensitive_box_text": "#721c24",
            "sensitive_headline_color": "#721c24",
            "card_bg": "#ffffff",
            "card_border": "#e1e4e8",
            "card_text": "#24292e",
            "summary_bg": "#f8f9fa",
            "summary_border": "#e1e4e8",
            "summary_text": "#333",
            "note_bg": "#f6f8fa",
            "note_border": "#b1b7c0",
            "note_text": "#586069",
            "selection_bg": "#bfdbfe",
            "selection_text": "#0f172a",
        }


def filter_note_html(matched, total, palette=None):
    """Shared "N of M records" match note for filtered evidence views."""
    color = palette["text_secondary"] if palette else "#586069"
    return (
        f'<div style="font-size: 12px; color: {color}; margin-bottom: 8px;">'
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
                                  headline_color=None, palette=None):
    """Render one evidence record with a headline-first layout.

    The headline carries the most important field, remaining fields follow
    as muted detail lines, and the source tag stays visible. Extension
    technical details render behind a Details control when a view context
    is supplied; otherwise everything renders inline (legacy behavior).
    Marker and headline color preserve established per-section accents
    (e.g. sensitive metadata warnings).
    """
    p = palette or get_theme_palette(False)
    headline, visible, hidden = parse_evidence_record(subcategory, value)
    source_html = (
        f' <span style="color: {p["text_muted"]}; font-size: 11px;">[Source: {html.escape(str(source))}]</span>'
        if source else ""
    )
    if " — " in headline and not headline_color:
        name_part, rest_part = headline.split(" — ", 1)
        headline_open = (
            f'<b>{html.escape(name_part)}</b>'
            f'<span style="color: {p["text_secondary"]};"> — {html.escape(rest_part)}</span>'
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
        f'<div style="font-size: 12px; margin-bottom: 2px; word-break: break-all; color: {p["text_primary"]};">'
        f'<span style="color: {p["bullet_color"]};">{html.escape(marker)}</span> {headline_open}{source_html}</div>'
    ]
    for detail in visible:
        lines.append(_detail_div(detail, p["detail_color"]))
    if hidden:
        if expanded:
            for detail in hidden:
                lines.append(_detail_div(detail, p["detail_expanded_color"]))
            if view_key is not None and record_key is not None:
                lines.append(
                    f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                    f'<a href="#evd-{view_key}-{record_key}-hide" style="color: {p["link_color"]};">'
                    f'Hide details</a></div>'
                )
        elif view_key is not None and record_key is not None:
            lines.append(
                f'<div style="font-size: 11px; margin: 0 0 3px 14px;">'
                f'<a href="#evd-{view_key}-{record_key}-show" style="color: {p["link_color"]};">'
                f'Details</a></div>'
            )
        else:
            for detail in hidden:
                lines.append(
                    f'<div style="font-size: 11px; color: {p["detail_color"]}; margin: 0 0 2px 14px; '
                    f'word-break: break-all;">{html.escape(detail)}</div>'
                )
    return "\n".join(lines)


def format_evidence_group_open(title_html, count, view_key=None, group_key=None,
                                collapsed=False, collapsible=True, palette=None):
    """Render an evidence group header, optionally with collapse controls.

    Returns (header_html, show_body). Collapsed groups hide their records
    behind an expand link; the records themselves are never discarded.
    """
    p = palette or get_theme_palette(False)
    if (view_key is not None and group_key is not None
            and collapsible and count > EVIDENCE_GROUP_COLLAPSE_THRESHOLD):
        if collapsed:
            return (
                f'{title_html} '
                f'<a href="#evd-{view_key}-g-{group_key}-show" style="color: {p["link_color"]}; '
                f'font-size: 11px; font-weight: normal;">Expand ({count} records hidden)</a>',
                False,
            )
        return (
            f'{title_html} '
            f'<a href="#evd-{view_key}-g-{group_key}-hide" style="color: {p["link_color"]}; '
            f'font-size: 11px; font-weight: normal;">Collapse</a>',
            True,
        )
    return title_html, True


def format_finding_evidence_html(evidence, preview_limit=FINDING_EVIDENCE_PREVIEW_LIMIT,
                                   expanded=False, card_index=None, palette=None):
    """Render finding evidence as readable bullet lines with a preview cap.

    When collapsed, at most preview_limit entries are shown with a "+N more"
    note and a Show-all link (card_index identifies the card to expand).
    When expanded, all entries render with a Show-less link. Full records
    always remain available in the Collected Evidence view.
    """
    p = palette or get_theme_palette(False)
    items = collect_finding_evidence_items(evidence)
    if not items:
        return f'<div style="font-size: 11px; color: {p["text_muted"]}; font-style: italic;">No evidence recorded.</div>'

    if expanded or len(items) <= preview_limit:
        shown = items
    else:
        shown = items[:preview_limit]
    lines = []
    for item in shown:
        lines.append(
            f'<div style="font-size: 11px; margin-bottom: 2px; word-break: break-all; color: {p["text_primary"]};">'
            f'<span style="color: {p["bullet_color"]};">•</span> {html.escape(item)}</div>'
        )
    remaining = len(items) - len(shown)
    if card_index is not None and (remaining > 0 or expanded):
        if expanded:
            lines.append(
                f'<div style="font-size: 11px; margin-top: 4px;">'
                f'<a href="#ev-{card_index}-hide" style="color: {p["link_color"]};">Show less</a>'
                f'<span style="color: {p["text_secondary"]};"> · full list also in Collected Evidence.</span></div>'
            )
        else:
            lines.append(
                f'<div style="font-size: 11px; color: {p["text_secondary"]}; font-style: italic; margin-top: 4px;">'
                f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
                f'<a href="#ev-{card_index}-show" style="color: {p["link_color"]};">Show all</a> · '
                f'see Collected Evidence for the complete records.</div>'
            )
    elif remaining > 0:
        lines.append(
            f'<div style="font-size: 11px; color: {p["text_secondary"]}; font-style: italic; margin-top: 4px;">'
            f'+{remaining} more evidence entr{"y" if remaining == 1 else "ies"} — '
            f'see Collected Evidence for the complete records.</div>'
        )
    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Footprint Analyzer")
        self.resize(920, 660)
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

        # Settings & Theming State
        self.app_settings = QSettings("DigitalFootprintAnalyzer", "Preferences")
        self.current_theme = str(self.app_settings.value("theme_mode", "system"))
        self.font_scale = int(self.app_settings.value("font_scale", 13))
        self.high_contrast = self.app_settings.value("high_contrast_selection", True, type=bool)
        self.evidence_preview_limit = int(self.app_settings.value("evidence_preview_limit", FINDING_EVIDENCE_PREVIEW_LIMIT))
        self.process_collector_mode = str(self.app_settings.value("process_collector_mode", "Fast & Resilient (Tasklist + PowerShell)"))
        self.network_timeout = int(self.app_settings.value("network_timeout", 10))
        self.home_module_cards = []
        self.home_sys_bar = None
        self.home_tips_card = None
        self.home_modules_header = None

        # Main widget and layout
        central_widget = QWidget()
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)

        # Sidebar navigation
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(160)
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

        self.sidebar.setCurrentRow(0)  # Default to Home
        self.apply_theme()

    def _detect_system_dark_mode(self) -> bool:
        """Detect whether host operating system prefers a dark theme."""
        if sys.platform.startswith("win"):
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                )
                val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                winreg.CloseKey(key)
                return val == 0
            except Exception:
                pass
        try:
            bg = self.palette().color(QPalette.ColorRole.Window)
            return bg.value() < 128
        except Exception:
            return False

    @property
    def is_dark_mode(self) -> bool:
        if self.current_theme == "dark":
            return True
        elif self.current_theme == "light":
            return False
        return self._detect_system_dark_mode()

    def get_palette(self) -> dict:
        return get_theme_palette(self.is_dark_mode)

    def _get_dark_qss(self) -> str:
        sel_bg = "#2563eb" if self.high_contrast else "#3b82f6"
        sel_fg = "#ffffff"
        font_sz = self.font_scale
        return f"""
            QMainWindow, QWidget#centralWidget {{
                background-color: #0f172a;
                color: #f8fafc;
                font-size: {font_sz}px;
            }}
            QListWidget {{
                background-color: #1e293b;
                color: #f1f5f9;
                border: none;
                border-right: 1px solid #334155;
                font-size: {font_sz}px;
            }}
            QListWidget::item {{
                padding: 10px 14px;
                border-radius: 6px;
                margin: 3px 6px;
            }}
            QListWidget::item:selected {{
                background-color: #2563eb;
                color: #ffffff;
                font-weight: bold;
            }}
            QListWidget::item:hover:!selected {{
                background-color: #334155;
                color: #f8fafc;
            }}
            QTabWidget::pane {{
                border: 1px solid #334155;
                background-color: #0f172a;
                border-radius: 6px;
            }}
            QTabBar::tab {{
                background-color: #1e293b;
                color: #94a3b8;
                padding: 8px 16px;
                border: 1px solid #334155;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-size: {font_sz}px;
            }}
            QTabBar::tab:selected {{
                background-color: #0f172a;
                color: #60a5fa;
                border-bottom: 2px solid #3b82f6;
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background-color: #334155;
                color: #f1f5f9;
            }}
            QTextBrowser, QTextEdit {{
                background-color: #0f172a;
                color: #f8fafc;
                border: 1px solid #334155;
                border-radius: 6px;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                font-size: {font_sz}px;
            }}
            QLineEdit {{
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #475569;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                font-size: {font_sz}px;
            }}
            QLineEdit:focus {{
                border: 1px solid #3b82f6;
            }}
            QComboBox {{
                background-color: #1e293b;
                color: #f8fafc;
                border: 1px solid #475569;
                border-radius: 6px;
                padding: 6px 10px;
                font-size: {font_sz}px;
            }}
            QComboBox QAbstractItemView {{
                background-color: #1e293b;
                color: #f8fafc;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                border: 1px solid #334155;
            }}
            QGroupBox {{
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 14px;
                padding-top: 12px;
                font-weight: bold;
                color: #60a5fa;
                font-size: {font_sz}px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 2px 8px;
                background-color: #0f172a;
            }}
            QPushButton {{
                background-color: #2563eb;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 600;
                font-size: {font_sz}px;
            }}
            QPushButton:hover {{
                background-color: #1d4ed8;
            }}
            QPushButton:pressed {{
                background-color: #1e40af;
            }}
            QPushButton:disabled {{
                background-color: #334155;
                color: #64748b;
            }}
            QLabel {{
                color: #f8fafc;
                font-size: {font_sz}px;
            }}
            QRadioButton, QCheckBox {{
                color: #f8fafc;
                spacing: 8px;
                font-size: {font_sz}px;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
        """

    def _get_light_qss(self) -> str:
        sel_bg = "#2563eb" if self.high_contrast else "#bfdbfe"
        sel_fg = "#ffffff" if self.high_contrast else "#0f172a"
        font_sz = self.font_scale
        return f"""
            QMainWindow, QWidget#centralWidget {{
                background-color: #f8fafc;
                color: #0f172a;
                font-size: {font_sz}px;
            }}
            QListWidget {{
                background-color: #ffffff;
                color: #334155;
                border: none;
                border-right: 1px solid #e2e8f0;
                font-size: {font_sz}px;
            }}
            QListWidget::item {{
                padding: 10px 14px;
                border-radius: 6px;
                margin: 3px 6px;
            }}
            QListWidget::item:selected {{
                background-color: #2563eb;
                color: #ffffff;
                font-weight: bold;
            }}
            QListWidget::item:hover:!selected {{
                background-color: #f1f5f9;
                color: #0f172a;
            }}
            QTabWidget::pane {{
                border: 1px solid #e2e8f0;
                background-color: #ffffff;
                border-radius: 6px;
            }}
            QTabBar::tab {{
                background-color: #f1f5f9;
                color: #64748b;
                padding: 8px 16px;
                border: 1px solid #e2e8f0;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-size: {font_sz}px;
            }}
            QTabBar::tab:selected {{
                background-color: #ffffff;
                color: #1d4ed8;
                border-bottom: 2px solid #2563eb;
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background-color: #e2e8f0;
                color: #0f172a;
            }}
            QTextBrowser, QTextEdit {{
                background-color: #ffffff;
                color: #0f172a;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                font-size: {font_sz}px;
            }}
            QLineEdit {{
                background-color: #ffffff;
                color: #0f172a;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                font-size: {font_sz}px;
            }}
            QLineEdit:focus {{
                border: 1px solid #3b82f6;
            }}
            QComboBox {{
                background-color: #ffffff;
                color: #0f172a;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 10px;
                font-size: {font_sz}px;
            }}
            QComboBox QAbstractItemView {{
                background-color: #ffffff;
                color: #0f172a;
                selection-background-color: {sel_bg};
                selection-color: {sel_fg};
                border: 1px solid #cbd5e1;
            }}
            QGroupBox {{
                border: 1px solid #cbd5e1;
                border-radius: 8px;
                margin-top: 14px;
                padding-top: 12px;
                font-weight: bold;
                color: #1e3a8a;
                font-size: {font_sz}px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 2px 8px;
                background-color: #f8fafc;
            }}
            QPushButton {{
                background-color: #2563eb;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 600;
                font-size: {font_sz}px;
            }}
            QPushButton:hover {{
                background-color: #1d4ed8;
            }}
            QPushButton:pressed {{
                background-color: #1e40af;
            }}
            QPushButton:disabled {{
                background-color: #e2e8f0;
                color: #94a3b8;
            }}
            QLabel {{
                color: #0f172a;
                font-size: {font_sz}px;
            }}
            QRadioButton, QCheckBox {{
                color: #0f172a;
                spacing: 8px;
                font-size: {font_sz}px;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
        """

    def set_theme_mode(self, mode: str):
        self.current_theme = mode
        self.app_settings.setValue("theme_mode", mode)
        self.apply_theme()

    def apply_theme(self, mode: str = None):
        if mode:
            self.current_theme = mode
            self.app_settings.setValue("theme_mode", mode)
        qss = self._get_dark_qss() if self.is_dark_mode else self._get_light_qss()
        self.setStyleSheet(qss)
        self._refresh_home_theme()
        # Re-render active views
        for view_key in ("sys", "browser", "file", "full", "public"):
            self._render_view_evidence(view_key)
            self._render_view_findings(view_key)

    def _refresh_home_theme(self):
        dark = self.is_dark_mode
        card_bg = "#1e293b" if dark else "#ffffff"
        card_border = "#334155" if dark else "#e2e8f0"
        card_hover_bg = "#243248" if dark else "#fbfdff"
        card_title_color = "#f8fafc" if dark else "#0f172a"
        card_desc_color = "#94a3b8" if dark else "#64748b"

        if self.home_sys_bar:
            self.home_sys_bar.setStyleSheet(f"""
                QFrame {{
                    background: {card_bg};
                    border: 1px solid {card_border};
                    border-radius: 8px;
                }}
            """)
        if self.home_tips_card:
            self.home_tips_card.setStyleSheet(f"""
                QFrame {{
                    background: {card_bg};
                    border: 1px solid {card_border};
                    border-radius: 10px;
                }}
            """)
        if self.home_modules_header:
            self.home_modules_header.setStyleSheet(f"color: {card_title_color}; margin-top: 4px;")

        for card in getattr(self, "home_module_cards", []):
            card.setStyleSheet(f"""
                QFrame {{
                    background: {card_bg};
                    border: 1px solid {card_border};
                    border-radius: 10px;
                }}
                QFrame:hover {{
                    border: 1px solid #3b82f6;
                    background: {card_hover_bg};
                }}
            """)
            title_lbl = getattr(card, "_title_lbl", None)
            if title_lbl:
                title_lbl.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {card_title_color}; background: transparent;")
            desc_lbl = getattr(card, "_desc_lbl", None)
            if desc_lbl:
                desc_lbl.setStyleSheet(f"font-size: 12px; color: {card_desc_color}; line-height: 1.4; background: transparent;")

    def _render_view_findings(self, view_key: str):
        result = self._last_results.get(view_key)
        if result is None:
            return
        area = self._findings_area_for(view_key)
        if area is None:
            return
        scrollbar = area.verticalScrollBar().value()
        findings_html = self.format_findings_html(
            result.findings,
            evidence_count=len(result.footprint_data or []),
            scan_status=result.status,
            expanded=self._expanded_cards.get(view_key, set()),
            summary=summarize_full_scan(result) if view_key == "full" else None,
            palette=self.get_palette(),
        )
        area.setHtml(findings_html)
        area.verticalScrollBar().setValue(scrollbar)

    def nav_to_system_footprint(self):
        self.sidebar.setCurrentRow(1)
        self.my_footprint_tabs.setCurrentIndex(0)

    def nav_to_browser_footprint(self):
        self.sidebar.setCurrentRow(1)
        self.my_footprint_tabs.setCurrentIndex(1)

    def nav_to_file_metadata(self):
        self.sidebar.setCurrentRow(1)
        self.my_footprint_tabs.setCurrentIndex(2)

    def nav_to_full_scan(self):
        self.sidebar.setCurrentRow(1)
        self.my_footprint_tabs.setCurrentIndex(3)

    def nav_to_public_lookup(self):
        self.sidebar.setCurrentRow(2)

    def init_home_page(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(15, 12, 15, 20)
        layout.setSpacing(16)

        # 1. Hero Header Banner
        hero_card = QFrame()
        hero_card.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0f172a, stop:0.55 #1e293b, stop:1 #1e3a8a);
                border-radius: 12px;
                border: 1px solid #334155;
            }
        """)
        hero_layout = QVBoxLayout(hero_card)
        hero_layout.setContentsMargins(24, 20, 24, 20)
        hero_layout.setSpacing(10)

        title_label = QLabel("🛡️ Digital Footprint Analyzer")
        title_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: bold; background: transparent;")
        hero_layout.addWidget(title_label)

        subtitle_label = QLabel(
            "An all-in-one local privacy intelligence and footprint reconnaissance suite. "
            "Audit your system configuration, examine browser extension traces, inspect file metadata for sensitive leaks, "
            "and check public breach databases."
        )
        subtitle_label.setWordWrap(True)
        subtitle_label.setStyleSheet("color: #cbd5e1; font-size: 13px; line-height: 1.5; background: transparent;")
        hero_layout.addWidget(subtitle_label)

        # Badges row
        badges_row = QHBoxLayout()
        badges_row.setSpacing(10)
        badge_style = """
            QLabel {
                background: rgba(255, 255, 255, 0.12);
                color: #e2e8f0;
                border: 1px solid rgba(255, 255, 255, 0.25);
                border-radius: 12px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 600;
            }
        """
        for text in ["🔒 100% Read-Only Inspection", "🛡️ Zero Cloud Data Collection", "⚡ Multi-Vector Privacy Audit"]:
            lbl = QLabel(text)
            lbl.setStyleSheet(badge_style)
            badges_row.addWidget(lbl)
        badges_row.addStretch()
        hero_layout.addLayout(badges_row)

        layout.addWidget(hero_card)

        # 2. System Snapshot Bar
        try:
            os_name = f"{platform.system()} {platform.release()}"
            arch = platform.machine()
            user_name = getpass.getuser()
        except Exception:
            os_name = "Windows"
            arch = "x64"
            user_name = "User"

        self.home_sys_bar = sys_bar = QFrame()
        sys_bar.setStyleSheet("""
            QFrame {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
            }
        """)
        sys_bar_layout = QHBoxLayout(sys_bar)
        sys_bar_layout.setContentsMargins(16, 9, 16, 9)
        sys_bar_layout.setSpacing(20)

        sys_bar_layout.addWidget(QLabel(f"💻 <span style='color: #64748b;'>Host OS:</span> <b style='color: #0f172a;'>{os_name} ({arch})</b>"))
        sys_bar_layout.addWidget(QLabel(f"👤 <span style='color: #64748b;'>Current User:</span> <b style='color: #0f172a;'>{user_name}</b>"))
        sys_bar_layout.addWidget(QLabel("⚡ <span style='color: #64748b;'>Engine:</span> <b style='color: #16a34a;'>Ready (4 Modules Active)</b>"))
        sys_bar_layout.addStretch()

        layout.addWidget(sys_bar)

        # Section Header: Audit Modules
        self.home_modules_header = modules_header = QLabel("<h3>Audit Modules</h3>")
        modules_header.setStyleSheet("color: #0f172a; margin-top: 4px;")
        layout.addWidget(modules_header)

        # 3. 2x2 Feature Modules Grid
        grid = QGridLayout()
        grid.setSpacing(14)

        def create_module_card(icon, title, category, description, btn_text, on_click):
            card = QFrame()
            card.setStyleSheet("""
                QFrame {
                    background: #ffffff;
                    border: 1px solid #e2e8f0;
                    border-radius: 10px;
                }
                QFrame:hover {
                    border: 1px solid #3b82f6;
                    background: #fbfdff;
                }
            """)
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(18, 16, 18, 16)
            c_layout.setSpacing(10)

            top_row = QHBoxLayout()
            icon_lbl = QLabel(icon)
            icon_lbl.setStyleSheet("font-size: 22px; background: transparent;")
            top_row.addWidget(icon_lbl)

            cat_lbl = QLabel(category)
            cat_lbl.setStyleSheet("background: #eff6ff; color: #1d4ed8; font-size: 11px; font-weight: bold; padding: 2px 8px; border-radius: 4px;")
            top_row.addWidget(cat_lbl)
            top_row.addStretch()
            c_layout.addLayout(top_row)

            title_lbl = QLabel(title)
            title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #0f172a; background: transparent;")
            c_layout.addWidget(title_lbl)
            card._title_lbl = title_lbl

            desc_lbl = QLabel(description)
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet("font-size: 12px; color: #64748b; line-height: 1.4; background: transparent;")
            desc_lbl.setMinimumHeight(44)
            c_layout.addWidget(desc_lbl)
            card._desc_lbl = desc_lbl

            btn = QPushButton(btn_text)
            btn.setStyleSheet("""
                QPushButton {
                    background: #2563eb;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 14px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background: #1d4ed8;
                }
                QPushButton:pressed {
                    background: #1e40af;
                }
            """)
            btn.clicked.connect(on_click)
            c_layout.addWidget(btn)

            return card

        card_sys = create_module_card(
            "🖥️",
            "System Footprint",
            "LOCAL SYSTEM",
            "Audit installed software from registry databases and inspect startup autorun programs that persist across reboots.",
            "Audit System Footprint →",
            self.nav_to_system_footprint
        )
        card_browser = create_module_card(
            "🌐",
            "Browser Footprint",
            "CHROMIUM BROWSERS",
            "Detect Google Chrome and Microsoft Edge profiles, inspect installed extensions, and resolve localized extension manifests.",
            "Audit Browser Footprint →",
            self.nav_to_browser_footprint
        )
        card_file = create_module_card(
            "📁",
            "File & Metadata Footprint",
            "MEDIA & EXIF",
            "Analyze JPEG and PNG images for embedded EXIF tags, GPS location markers, camera serials, and author timestamps.",
            "Inspect File Metadata →",
            self.nav_to_file_metadata
        )
        card_public = create_module_card(
            "🔍",
            "Public Footprint Lookup",
            "OSINT RECONNAISSANCE",
            "Check email exposure against known breach datasets and search for username presence across 300+ online platforms.",
            "Launch Public Lookup →",
            self.nav_to_public_lookup
        )

        self.home_module_cards = [card_sys, card_browser, card_file, card_public]

        grid.addWidget(card_sys, 0, 0)
        grid.addWidget(card_browser, 0, 1)
        grid.addWidget(card_file, 1, 0)
        grid.addWidget(card_public, 1, 1)
        layout.addLayout(grid)

        # 4. Security & Privacy Best Practices Card
        self.home_tips_card = tips_card = QFrame()
        tips_card.setStyleSheet("""
            QFrame {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
            }
        """)
        tips_layout = QVBoxLayout(tips_card)
        tips_layout.setContentsMargins(18, 16, 18, 16)
        tips_layout.setSpacing(10)

        tips_title = QLabel("💡 Privacy Hygiene & Exposure Reduction Tips")
        tips_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #0f172a; background: transparent;")
        tips_layout.addWidget(tips_title)

        tips_text = QLabel(
            "• <b>Extension Pruning:</b> Periodically uninstall browser extensions you no longer use; extensions often hold broad page permissions.<br>"
            "• <b>EXIF Scrubbing:</b> Photos captured on smartphones and cameras frequently store exact GPS coordinates in EXIF headers before sharing.<br>"
            "• <b>Startup Optimization:</b> Audit startup applications to reduce unwanted background network telemetry and shorten boot time.<br>"
            "• <b>Breach Monitoring:</b> When your email appears in a public breach, immediately rotate passwords and enable Multi-Factor Authentication (MFA)."
        )
        tips_text.setWordWrap(True)
        tips_text.setStyleSheet("color: #475569; font-size: 12px; line-height: 1.6; background: transparent;")
        tips_layout.addWidget(tips_text)

        layout.addWidget(tips_card)

        # Footer
        footer_layout = QHBoxLayout()
        footer_label = QLabel("Digital Footprint Analyzer • v1.0 • Privacy-Preserving Security Inspection")
        footer_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        footer_layout.addWidget(footer_label)
        footer_layout.addStretch()
        layout.addLayout(footer_layout)

        scroll.setWidget(container)

        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)
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
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 16, 20, 20)
        layout.setSpacing(14)

        # Header
        header = QLabel("<h2>⚙️ Settings &amp; Preferences</h2>")
        header.setStyleSheet("margin-bottom: 2px;")
        layout.addWidget(header)
        subtitle = QLabel("Configure appearance, scan engine behavior, evidence readability, and privacy controls.")
        subtitle.setStyleSheet("color: #64748b; font-size: 13px; margin-bottom: 8px;")
        layout.addWidget(subtitle)

        # Status feedback banner (brief notification when settings change)
        self.settings_status_label = QLabel("")
        self.settings_status_label.setStyleSheet("color: #16a34a; font-weight: bold; font-size: 12px;")
        layout.addWidget(self.settings_status_label)

        # ----------------------------------------------------
        # Group 1: Appearance & Readability
        # ----------------------------------------------------
        theme_group = QGroupBox("🎨 Appearance & Theming")
        theme_layout = QVBoxLayout(theme_group)
        theme_layout.setSpacing(10)

        theme_desc = QLabel("Choose your preferred color theme or match your operating system theme:")
        theme_desc.setStyleSheet("color: #64748b; font-size: 12px;")
        theme_layout.addWidget(theme_desc)

        self.theme_btn_group = QButtonGroup(self)
        theme_row = QHBoxLayout()
        theme_row.setSpacing(20)

        self.theme_system_rb = QRadioButton("🖥️ System Default (Auto)")
        self.theme_light_rb = QRadioButton("☀️ Light Mode")
        self.theme_dark_rb = QRadioButton("🌙 Dark Mode")

        self.theme_btn_group.addButton(self.theme_system_rb, 0)
        self.theme_btn_group.addButton(self.theme_light_rb, 1)
        self.theme_btn_group.addButton(self.theme_dark_rb, 2)

        theme_row.addWidget(self.theme_system_rb)
        theme_row.addWidget(self.theme_light_rb)
        theme_row.addWidget(self.theme_dark_rb)
        theme_row.addStretch()
        theme_layout.addLayout(theme_row)

        # Set active radio button based on current setting
        if self.current_theme == "light":
            self.theme_light_rb.setChecked(True)
        elif self.current_theme == "dark":
            self.theme_dark_rb.setChecked(True)
        else:
            self.theme_system_rb.setChecked(True)

        self.theme_system_rb.toggled.connect(lambda c: c and self._on_theme_radio_changed("system"))
        self.theme_light_rb.toggled.connect(lambda c: c and self._on_theme_radio_changed("light"))
        self.theme_dark_rb.toggled.connect(lambda c: c and self._on_theme_radio_changed("dark"))

        # Selection contrast & Font scale options
        options_row = QHBoxLayout()
        options_row.setSpacing(20)

        self.contrast_checkbox = QCheckBox("High-contrast text selection (Royal Blue with white text)")
        self.contrast_checkbox.setToolTip("Eliminates white-on-white selection blocks and makes selected lines clearly legible in dark and light modes.")
        self.contrast_checkbox.setChecked(self.high_contrast)
        self.contrast_checkbox.toggled.connect(self._on_contrast_toggled)
        options_row.addWidget(self.contrast_checkbox)

        options_row.addSpacing(20)
        font_lbl = QLabel("Text scale:")
        options_row.addWidget(font_lbl)
        self.font_scale_combo = QComboBox()
        self.font_scale_combo.addItems(["Compact (12px)", "Standard (13px)", "Large (14px)", "Extra Large (16px)"])
        scale_map = {12: 0, 13: 1, 14: 2, 16: 3}
        self.font_scale_combo.setCurrentIndex(scale_map.get(self.font_scale, 1))
        self.font_scale_combo.currentIndexChanged.connect(self._on_font_scale_changed)
        options_row.addWidget(self.font_scale_combo)
        options_row.addStretch()

        theme_layout.addLayout(options_row)
        layout.addWidget(theme_group)

        # ----------------------------------------------------
        # Group 2: Scan & Engine Configuration
        # ----------------------------------------------------
        engine_group = QGroupBox("⚙️ Scan & Engine Preferences")
        engine_layout = QVBoxLayout(engine_group)
        engine_layout.setSpacing(12)

        # Windows Process Collector Tier
        proc_row = QHBoxLayout()
        proc_lbl = QLabel("Windows Process Collector:")
        proc_lbl.setFixedWidth(200)
        self.process_mode_combo = QComboBox()
        self.process_mode_combo.addItems([
            "Fast & Resilient (Tasklist + PowerShell + WMI)",
            "Standard (Tasklist CLI only)",
            "PowerShell CIM/WMI Deep Query"
        ])
        if "Standard" in self.process_collector_mode:
            self.process_mode_combo.setCurrentIndex(1)
        elif "PowerShell" in self.process_collector_mode:
            self.process_mode_combo.setCurrentIndex(2)
        else:
            self.process_mode_combo.setCurrentIndex(0)
        self.process_mode_combo.currentIndexChanged.connect(self._on_process_mode_changed)
        proc_row.addWidget(proc_lbl)
        proc_row.addWidget(self.process_mode_combo, stretch=1)
        engine_layout.addLayout(proc_row)

        # Findings Preview Limit
        preview_row = QHBoxLayout()
        preview_lbl = QLabel("Finding Evidence Preview Cap:")
        preview_lbl.setFixedWidth(200)
        self.preview_limit_combo = QComboBox()
        self.preview_limit_combo.addItems([
            "5 entries per card",
            "10 entries per card (Default)",
            "20 entries per card",
            "Unlimited (Show all records)"
        ])
        cap_map = {5: 0, 10: 1, 20: 2, 999999: 3}
        self.preview_limit_combo.setCurrentIndex(cap_map.get(self.evidence_preview_limit, 1))
        self.preview_limit_combo.currentIndexChanged.connect(self._on_preview_limit_changed)
        preview_row.addWidget(preview_lbl)
        preview_row.addWidget(self.preview_limit_combo, stretch=1)
        engine_layout.addLayout(preview_row)

        # OSINT Timeout
        timeout_row = QHBoxLayout()
        timeout_lbl = QLabel("Public Lookup Network Timeout:")
        timeout_lbl.setFixedWidth(200)
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems([
            "5 seconds (Quick check)",
            "10 seconds (Standard, Recommended)",
            "20 seconds (Deep lookup)"
        ])
        t_map = {5: 0, 10: 1, 20: 2}
        self.timeout_combo.setCurrentIndex(t_map.get(self.network_timeout, 1))
        self.timeout_combo.currentIndexChanged.connect(self._on_timeout_changed)
        timeout_row.addWidget(timeout_lbl)
        timeout_row.addWidget(self.timeout_combo, stretch=1)
        engine_layout.addLayout(timeout_row)

        layout.addWidget(engine_group)

        # ----------------------------------------------------
        # Group 3: Privacy & Session Memory Controls
        # ----------------------------------------------------
        privacy_group = QGroupBox("🔒 Privacy & Session Controls")
        privacy_layout = QVBoxLayout(privacy_group)
        privacy_layout.setSpacing(10)

        cache_row = QHBoxLayout()
        self.cache_count_label = QLabel(self._get_cache_status_text())
        cache_row.addWidget(self.cache_count_label, stretch=1)
        self.clear_cache_btn = QPushButton("🗑️ Clear Cached Scan Results")
        self.clear_cache_btn.clicked.connect(self.clear_all_cached_results)
        cache_row.addWidget(self.clear_cache_btn)
        privacy_layout.addLayout(cache_row)

        privacy_note = QFrame()
        privacy_note.setStyleSheet("""
            QFrame {
                background: rgba(37, 99, 235, 0.08);
                border: 1px solid rgba(37, 99, 235, 0.25);
                border-radius: 6px;
                padding: 6px;
            }
        """)
        note_layout = QVBoxLayout(privacy_note)
        note_layout.setContentsMargins(10, 8, 10, 8)
        note_text = QLabel(
            "🛡️ <b>Local-First Privacy Guarantee:</b> All system footprint audits, browser extension traces, "
            "and file metadata extractions run 100% locally on your computer. No collected data or telemetry "
            "is transmitted to external servers."
        )
        note_text.setWordWrap(True)
        note_layout.addWidget(note_text)
        privacy_layout.addWidget(privacy_note)

        layout.addWidget(privacy_group)

        # ----------------------------------------------------
        # Group 4: System Information & Diagnostics
        # ----------------------------------------------------
        diag_group = QGroupBox("ℹ️ System Diagnostics & Information")
        diag_layout = QVBoxLayout(diag_group)
        diag_layout.setSpacing(8)

        diag_grid = QGridLayout()
        diag_grid.setSpacing(8)

        import PySide6
        py_ver = f"{sys.version.split()[0]} ({platform.python_implementation()})"
        qt_ver = f"PySide6 {getattr(PySide6, '__version__', '6.x')} (Qt 6)"
        os_ver = f"{platform.system()} {platform.release()} ({platform.machine()})"

        diag_grid.addWidget(QLabel("<b>Application:</b>"), 0, 0)
        diag_grid.addWidget(QLabel("Digital Footprint Analyzer v1.0.0"), 0, 1)

        diag_grid.addWidget(QLabel("<b>Python Runtime:</b>"), 1, 0)
        diag_grid.addWidget(QLabel(py_ver), 1, 1)

        diag_grid.addWidget(QLabel("<b>GUI Framework:</b>"), 2, 0)
        diag_grid.addWidget(QLabel(qt_ver), 2, 1)

        diag_grid.addWidget(QLabel("<b>Host System:</b>"), 3, 0)
        diag_grid.addWidget(QLabel(os_ver), 3, 1)

        diag_layout.addLayout(diag_grid)

        # Reset button
        reset_row = QHBoxLayout()
        reset_row.addStretch()
        self.reset_btn = QPushButton("🔄 Reset All Settings to Defaults")
        self.reset_btn.setStyleSheet("""
            QPushButton {
                background: #64748b;
                color: white;
                border-radius: 6px;
                padding: 6px 14px;
            }
            QPushButton:hover {
                background: #475569;
            }
        """)
        self.reset_btn.clicked.connect(self.reset_settings_to_defaults)
        reset_row.addWidget(self.reset_btn)
        diag_layout.addLayout(reset_row)

        layout.addWidget(diag_group)
        layout.addStretch()

        scroll.setWidget(container)

        page = QWidget()
        p_layout = QVBoxLayout(page)
        p_layout.setContentsMargins(0, 0, 0, 0)
        p_layout.addWidget(scroll)
        self.pages.addWidget(page)

    def _on_theme_radio_changed(self, mode: str):
        self.set_theme_mode(mode)
        self._notify_settings_changed(f"Theme updated to: {mode.capitalize()}")

    def _on_contrast_toggled(self, checked: bool):
        self.high_contrast = checked
        self.app_settings.setValue("high_contrast_selection", checked)
        self.apply_theme()
        status = "High-contrast selection enabled" if checked else "Standard selection enabled"
        self._notify_settings_changed(status)

    def _on_font_scale_changed(self, index: int):
        scales = [12, 13, 14, 16]
        if 0 <= index < len(scales):
            self.font_scale = scales[index]
            self.app_settings.setValue("font_scale", self.font_scale)
            self.apply_theme()
            self._notify_settings_changed(f"Font scale set to {self.font_scale}px")

    def _on_process_mode_changed(self, index: int):
        modes = [
            "Fast & Resilient (Tasklist + PowerShell + WMI)",
            "Standard (Tasklist CLI only)",
            "PowerShell CIM/WMI Deep Query"
        ]
        if 0 <= index < len(modes):
            self.process_collector_mode = modes[index]
            self.app_settings.setValue("process_collector_mode", self.process_collector_mode)
            self._notify_settings_changed("Process collector mode saved")

    def _on_preview_limit_changed(self, index: int):
        limits = [5, 10, 20, 999999]
        if 0 <= index < len(limits):
            self.evidence_preview_limit = limits[index]
            self.app_settings.setValue("evidence_preview_limit", self.evidence_preview_limit)
            self._notify_settings_changed("Evidence preview limit updated")
            for view_key in ("sys", "browser", "file", "full", "public"):
                self._render_view_findings(view_key)

    def _on_timeout_changed(self, index: int):
        timeouts = [5, 10, 20]
        if 0 <= index < len(timeouts):
            self.network_timeout = timeouts[index]
            self.app_settings.setValue("network_timeout", self.network_timeout)
            self._notify_settings_changed(f"Network timeout set to {self.network_timeout}s")

    def _get_cache_status_text(self) -> str:
        count = sum(1 for v in self._last_results.values() if v is not None)
        return f"Currently holding <b>{count}</b> scan result{'s' if count != 1 else ''} in memory."

    def clear_all_cached_results(self):
        self._last_results.clear()
        self._expanded_cards.clear()
        self._collapsed_evidence.clear()
        self._expanded_evidence_records.clear()

        for attr in ("sys_findings_area", "sys_results_area", "browser_findings_area",
                     "browser_results_area", "file_findings_area", "file_results_area",
                     "full_scan_findings_area", "full_scan_results_area",
                     "public_findings_area", "results_area"):
            area = getattr(self, attr, None)
            if area:
                area.clear()

        for attr in ("sys_status_label", "browser_status_label", "file_status_label",
                     "full_scan_status_label", "status_label"):
            lbl = getattr(self, attr, None)
            if lbl:
                lbl.setText("")

        if hasattr(self, "cache_count_label"):
            self.cache_count_label.setText(self._get_cache_status_text())
        self._notify_settings_changed("All in-memory scan results cleared.")

    def reset_settings_to_defaults(self):
        self.app_settings.clear()
        self.current_theme = "system"
        self.font_scale = 13
        self.high_contrast = True
        self.evidence_preview_limit = FINDING_EVIDENCE_PREVIEW_LIMIT
        self.process_collector_mode = "Fast & Resilient (Tasklist + PowerShell)"
        self.network_timeout = 10

        if hasattr(self, "theme_system_rb"):
            self.theme_system_rb.setChecked(True)
        if hasattr(self, "contrast_checkbox"):
            self.contrast_checkbox.setChecked(True)
        if hasattr(self, "font_scale_combo"):
            self.font_scale_combo.setCurrentIndex(1)
        if hasattr(self, "process_mode_combo"):
            self.process_mode_combo.setCurrentIndex(0)
        if hasattr(self, "preview_limit_combo"):
            self.preview_limit_combo.setCurrentIndex(1)
        if hasattr(self, "timeout_combo"):
            self.timeout_combo.setCurrentIndex(1)

        self.apply_theme()
        self._notify_settings_changed("Settings reset to factory defaults.")

    def _notify_settings_changed(self, message: str):
        if hasattr(self, "settings_status_label"):
            self.settings_status_label.setText(f"✓ {message}")
            QTimer.singleShot(4000, lambda: self.settings_status_label.setText("") if hasattr(self, "settings_status_label") else None)

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
        p = self.get_palette()
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
                expanded_records=expanded_records, palette=p)
            area = self.sys_results_area
        elif view_key == "browser":
            body = self.format_browser_evidence_html(
                visible, view_key="browser", collapsed=collapsed,
                expanded_records=expanded_records, palette=p)
            area = self.browser_results_area
        elif view_key == "file":
            body = self.format_file_evidence_html(
                visible, view_key="file", collapsed=collapsed,
                expanded_records=expanded_records, palette=p)
            area = self.file_results_area
        elif view_key == "public":
            body = self.format_public_evidence_html(
                footprint, result.findings, palette=p)
            area = self.results_area
        else:
            return
        if query or subcategories is not None or exclude is not None:
            body = filter_note_html(len(visible), len(footprint), palette=p) + body
        if not visible and footprint:
            body += (f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; '
                     f'border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; '
                     f'color: {p["text_secondary"]};">No records match the current filter. Clear the search '
                     f'or choose a different group to see more evidence.</div>')
        area.setHtml(body)

    def _render_full_scan_evidence(self):
        result = self._last_results.get("full")
        if result is None:
            return
        p = self.get_palette()
        self.full_scan_results_area.setHtml(self.format_full_scan_evidence_html(
            result,
            query=self.full_evidence_search.text(),
            module=self._full_evidence_module_filter(),
            palette=p,
        ))

    # --------------------------------------------------------
    # HTML FORMATTERS FOR FINDINGS AND COLLECTED EVIDENCE
    # --------------------------------------------------------

    def format_findings_html(self, findings, evidence_count=0, scan_status=None,
                               expanded=frozenset(), summary=None, palette=None):
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
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))
        is_dark = p.get("is_dark", False)

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
            if is_dark:
                status_styles = {
                    "COMPLETED": ("#4ade80", "#064e3b", "#047857"),
                    "PARTIAL": ("#fbbf24", "#451a03", "#b45309"),
                    "ERROR": ("#f87171", "#450a0a", "#b91c1c"),
                }
            else:
                status_styles = {
                    "COMPLETED": ("#22863a", "#e6f4ea", "#b7e0c3"),
                    "PARTIAL": ("#b04300", "#fff5e6", "#f0c48c"),
                    "ERROR": ("#cb2431", "#ffeef0", "#f5b5ba"),
                }
            status_key = str(scan_status).strip().upper()
            text_color, bg_color, border_color = status_styles.get(
                status_key, (p["text_secondary"], p["box_bg"], p["box_border"])
            )
            guidance = SCAN_STATUS_GUIDANCE.get(status_key, "")
            guidance_html = (
                f'<span style="color: {p["text_secondary"]};"> — {html.escape(guidance)}</span>'
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
            if is_dark:
                chip_style = (
                    "background-color: #334155; color: #f8fafc;"
                    if count else "background-color: #1e293b; color: #64748b;"
                )
            else:
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
        <div style="font-family: sans-serif; margin-bottom: 8px; font-size: 12px; color: {p["text_primary"]};">
            <b>By severity:</b> {"&nbsp;&nbsp;".join(severity_chips)}
        </div>
        """

        # Per-module outcome rows supplied by the display summary, if any.
        module_rows = ""
        if summary and summary.get("modules"):
            if is_dark:
                state_styles = {
                    "completed": ("#4ade80", "✓"),
                    "limited": ("#fbbf24", "⚠"),
                    "failed": ("#f87171", "✕"),
                    "skipped": ("#94a3b8", "⊘"),
                    "unknown": ("#64748b", "?"),
                }
            else:
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
                    f'<div style="font-size: 12px; margin-bottom: 2px; color: {p["text_primary"]};">'
                    f'<span style="color: {color}; font-weight: bold;">{mark}</span> '
                    f'<b>{html.escape(mod.get("name", "?"))}:</b> '
                    f'{html.escape(mod.get("note", ""))}</div>'
                )
            module_rows = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 6px;">
            <div style="font-size: 12px; font-weight: bold; color: {p["text_primary"]}; margin-bottom: 4px;">Modules:</div>
            {"".join(row_lines)}
        </div>
        """

        # Limitations are scan-coverage notes, never privacy exposures.
        limitation_note = ""
        if limitation_count > 0:
            limitation_note = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {p["note_bg"]}; border: 1px dotted {p["note_border"]}; border-radius: 6px; font-size: 11px; color: {p["note_text"]};">
            <b>Scan Limitations ({limitation_count}):</b> notes about sources that could not be checked
            (unsupported platforms, locked profiles, or failed modules). These describe scan coverage,
            not confirmed privacy exposures.
        </div>
        """

        # Build Scan Summary Header Banner. Pills flow inline so the summary
        # wraps gracefully on narrow windows instead of squeezing one row.
        if is_dark:
            tot_style = "background-color: #334155; color: #f8fafc;"
            con_style = "background-color: #450a0a; color: #f87171;"
            obs_style = "background-color: #172554; color: #60a5fa;"
            evi_style = "background-color: #334155; color: #cbd5e1;"
        else:
            tot_style = "background-color: #e1e4e8; color: #24292e;"
            con_style = "background-color: #ffeef0; color: #cb2431;"
            obs_style = "background-color: #f1f8ff; color: #0366d6;"
            evi_style = "background-color: #f6f8fa; color: #444d56;"

        summary_html = f"""
        {status_banner}
        {severity_row}
        {module_rows}
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 6px 12px; background-color: {p["summary_bg"]}; border: 1px solid {p["summary_border"]}; border-radius: 6px; font-size: 12px; color: {p["summary_text"]}; line-height: 2;">
            <b>SCAN SUMMARY:</b>
            <span style="margin-left: 8px;"><b>Total Findings:</b> <span style="{tot_style} font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{total_findings}</span></span>
            <span style="margin-left: 8px;"><b>Concerns:</b> <span style="{con_style} font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{concerns_count}</span></span>
            <span style="margin-left: 8px;"><b>Observations:</b> <span style="{obs_style} font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{observations_count}</span></span>
            <span style="margin-left: 8px;"><b>Evidence Items:</b> <span style="{evi_style} font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{evidence_count}</span></span>
        </div>
        {limitation_note}
        """

        if not findings:
            failure_note = ""
            if scan_status and str(scan_status).strip().upper() == "ERROR":
                err_bg = "#450a0a" if is_dark else "#ffeef0"
                err_border = "#b91c1c" if is_dark else "#f5b5ba"
                err_text = "#fca5a5" if is_dark else "#86181d"
                failure_note = f"""
                <div style="padding: 12px; border: 1px solid {err_border}; border-radius: 6px; background-color: {err_bg}; color: {err_text}; margin-top: 4px; font-size: 12px;">
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
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FINDINGS ({total_findings} detected) ===</div>'
        ]

        for card_index, f in regular:
            cat = getattr(f, "category", "Observation") or "Observation"
            sev = f.severity or "Info"
            rule_id = getattr(f, "rule_id", None)
            limitations = getattr(f, "limitations", None)

            # Restrained, distinct badge and border color palette
            is_concern = (cat == "Concern")
            if is_dark:
                if is_concern:
                    cat_badge_bg = "#dc2626" if sev in ("High", "Critical") else "#ea580c"
                    card_border = "#ef4444" if sev in ("High", "Critical") else "#f97316"
                    card_bg = "#261316" if sev in ("High", "Critical") else "#291809"
                    title_color = "#f87171" if sev in ("High", "Critical") else "#fb923c"
                else:
                    cat_badge_bg = "#2563eb"
                    card_border = "#3b82f6"
                    card_bg = "#0f1d36"
                    title_color = "#60a5fa"
                sev_colors = {
                    "Critical": "#dc2626",
                    "High": "#dc2626",
                    "Medium": "#ea580c",
                    "Low": "#2563eb",
                    "Info": "#38bdf8"
                }
            else:
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
                f.evidence, expanded=(card_index in expanded), card_index=card_index, palette=p
            )
            evidence_heading = (
                f"Evidence ({evidence_count_for_card} "
                f"entr{'y' if evidence_count_for_card == 1 else 'ies'}):"
                if evidence_count_for_card
                else "Evidence:"
            )

            rule_html = f'<span style="font-size: 11px; color: {p["text_muted"]}; font-family: monospace;">Rule: {html.escape(rule_id)}</span>' if rule_id else ""
            limitations_html = (
                f'<div style="font-size: 11px; color: {p["text_secondary"]}; font-style: italic; margin-top: 5px; padding-top: 4px; border-top: 1px dotted {p["card_border"]};">'
                f'<b>Scope Limitation:</b> {html.escape(limitations)}</div>'
            ) if limitations else ""

            evi_box_bg = "#111827" if is_dark else "#f6f8fa"
            evi_box_border = "#374151" if is_dark else "#e1e4e8"
            evi_box_text = "#f3f4f6" if is_dark else "#24292e"

            card = f"""
            <div style="border: 1px solid {p['card_border']}; border-left: 4px solid {card_border}; border-radius: 4px; background-color: {card_bg}; padding: 6px 10px; margin-bottom: 8px;">
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
                <div style="font-size: 11px; color: {p['text_secondary']}; margin-bottom: 4px;">
                    {html.escape(sev_guidance)} · {html.escape(cat_guidance)}
                </div>
                <div style="font-size: 12px; color: {p['text_primary']}; line-height: 1.4; margin-bottom: 4px;">
                    {html.escape(f.description)}
                </div>
                <div style="background-color: {evi_box_bg}; border: 1px solid {evi_box_border}; border-radius: 3px; padding: 4px 8px; font-family: monospace; font-size: 11px; color: {evi_box_text}; word-break: break-all;">
                    <b>{html.escape(evidence_heading)}</b>
                    {evidence_block}
                </div>
                {limitations_html}
            </div>
            """
            cards.append(card)

        if coverage:
            coverage_blocks = [
                self._format_coverage_block(f, card_index, card_index in expanded, palette=p)
                for card_index, f in coverage
            ]
            cards.append(f"""
            <div style="font-weight: bold; font-size: 13px; margin: 12px 0 8px; color: {p['text_primary']};">=== COVERAGE &amp; LIMITATIONS ({len(coverage)} noted) ===</div>
            <div style="font-family: sans-serif; font-size: 11px; color: {p['text_secondary']}; margin-bottom: 8px; line-height: 1.4;">
                A browser listed as not detected was simply not found on this system. A missing profile
                directory is not automatically a vulnerability. An unsupported browser was not scanned,
                which is not the same as a failed scan. Unchecked sources are coverage gaps — never
                confirmed exposures.
            </div>
            {"".join(coverage_blocks)}
            """)

        cards.append('</div>')
        return "\n".join(cards)

    def _format_coverage_block(self, f, card_index, is_expanded, palette=None):
        """Render one coverage/limitation finding without duplicating data.

        Description lines render directly. The evidence box is skipped when
        every evidence entry already appears in the description (e.g. source
        paths, limitation messages), since re-rendering it would duplicate
        the same content. Long description lists are previewed with the
        shared Show-all/Show-less mechanism.
        """
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))
        is_dark = p.get("is_dark", False)

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
        desc_lines = [part.strip() for part in str(f.description or "").split("|")]
        desc_lines = [part for part in desc_lines if part]
        items = collect_finding_evidence_items(f.evidence)
        description_text = str(f.description or "")
        duplicates = bool(items) and all(item in description_text for item in items)

        link_color = p["link_color"]
        evi_box_bg = "#111827" if is_dark else "#f6f8fa"
        evi_box_border = "#374151" if is_dark else "#e1e4e8"
        evi_box_text = "#f3f4f6" if is_dark else "#24292e"

        if duplicates:
            if len(desc_lines) > COVERAGE_DESCRIPTION_PREVIEW_LIMIT and not is_expanded:
                shown = desc_lines[:COVERAGE_DESCRIPTION_PREVIEW_LIMIT]
                more = len(desc_lines) - len(shown)
                toggle = (
                    f'<div style="font-size: 11px; color: {p["text_secondary"]}; font-style: italic; margin-top: 4px;">'
                    f'+{more} more — '
                    f'<a href="#ev-{card_index}-show" style="color: {link_color};">Show all</a></div>'
                )
            else:
                shown = desc_lines
                toggle = ""
                if len(desc_lines) > COVERAGE_DESCRIPTION_PREVIEW_LIMIT and is_expanded:
                    toggle = (
                        f'<div style="font-size: 11px; margin-top: 4px;">'
                        f'<a href="#ev-{card_index}-hide" style="color: {link_color};">Show less</a></div>'
                    )
            desc_html = "".join(
                f'<div style="font-size: 12px; color: {p["text_primary"]}; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(part)}</div>'
                for part in shown
            ) + toggle
            evidence_html = ""
        else:
            desc_html = "".join(
                f'<div style="font-size: 12px; color: {p["text_primary"]}; margin-bottom: 2px; '
                f'word-break: break-all;">{html.escape(part)}</div>'
                for part in desc_lines
            )
            evidence_html = f"""
                <div style="background-color: {evi_box_bg}; border: 1px solid {evi_box_border}; border-radius: 3px; padding: 4px 8px; margin-top: 5px; font-size: 11px; color: {evi_box_text}; word-break: break-all;">
                    {format_finding_evidence_html(f.evidence, expanded=is_expanded, card_index=card_index, palette=p)}
                </div>"""

        return f"""
            <div style="border: 1px solid {p['card_border']}; border-radius: 4px; background-color: {p['box_bg']}; padding: 8px 10px; margin-bottom: 8px;">
                <div style="font-size: 12px; font-weight: bold; color: {p['text_primary']}; margin-bottom: 3px;">
                    {html.escape(f.title)}
                </div>
                <div style="font-size: 11px; color: {p['text_secondary']}; font-style: italic; margin-bottom: 5px;">
                    {html.escape(intro)}
                </div>
                {desc_html}{evidence_html}
            </div>
                """

    def format_system_evidence_html(self, footprint_data, view_key=None,
                                      collapsed=frozenset(), expanded_records=frozenset(),
                                      palette=None):
        """Formats System Footprint collected evidence with structured sections and word-wrap.

        Optional view_key enables group collapse controls and collapsible
        record details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))

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
                    palette=p,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed, palette=p,
            )
            lines.append(header)
            if show_body:
                lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FOOTPRINT DATA ===</div>',
            f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">System Footprint:</div>'
        ]

        if system_info:
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for fd in system_info:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; color: {p["text_primary"]};"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: {p["text_muted"]}; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if startups:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Startup Applications ({len(startups)} detected):</div>', "startups", startups)

        if installed_apps:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Installed Applications ({len(installed_apps)} detected):</div>', "installed_apps", installed_apps)

        if processes:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Running Processes ({len(processes)} detected):</div>', "processes", processes)

        lines.append('</div>')
        return "\n".join(lines)

    def format_browser_evidence_html(self, footprint_data, view_key=None,
                                       collapsed=frozenset(), expanded_records=frozenset(),
                                       palette=None):
        """Formats Browser Footprint collected evidence with structured sections and word-wrap.

        Optional view_key enables group collapse controls and collapsible
        extension details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))

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
                    palette=p,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed, palette=p,
            )
            lines.append(header)
            if show_body:
                lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
                lines.append(_records(items, group))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FOOTPRINT DATA ===</div>'
        ]

        if browsers:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Detected Browsers ({len(browsers)}):</div>', "browsers", browsers)

        if extensions:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Installed Extensions ({len(extensions)}):</div>', "extensions", extensions)

        if coverage:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Scan Coverage Notes:</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for c in coverage:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; color: {p["text_primary"]};">{html.escape(str(c.value))}</div>')
            lines.append('</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_file_evidence_html(self, footprint_data, view_key=None,
                                    collapsed=frozenset(), expanded_records=frozenset(),
                                    palette=None):
        """Formats File & Metadata collected evidence.

        Optional view_key enables group collapse controls and collapsible
        record details; without it every record renders fully (legacy).
        """
        collapsed = set(collapsed) if collapsed else set()
        expanded_records = set(expanded_records) if expanded_records else set()
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))

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

        sensitive_box = f'<div style="background-color: {p["sensitive_box_bg"]}; border: 1px solid {p["sensitive_box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["sensitive_box_text"]};">'

        def _records(items, group, marker="•", headline_color=None):
            return "\n".join(
                format_evidence_record_html(
                    fd.subcategory, fd.value, fd.source,
                    view_key=view_key,
                    record_key=f"{group}:{i}",
                    expanded=f"{group}:{i}" in expanded_records,
                    marker=marker,
                    headline_color=headline_color,
                    palette=p,
                )
                for i, fd in enumerate(items)
            )

        def _group(title_html, group, items, box_open=None, marker="•",
                   headline_color=None):
            header, show_body = format_evidence_group_open(
                title_html, len(items), view_key=view_key, group_key=group,
                collapsed=group in collapsed, palette=p,
            )
            lines.append(header)
            if show_body:
                lines.append(box_open or f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
                lines.append(_records(items, group, marker=marker,
                                      headline_color=headline_color))
                lines.append('</div>')

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FILE & METADATA FOOTPRINT ===</div>'
        ]

        if file_details:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">[File Details]</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for item in file_details:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all; color: {p["text_primary"]};">• {html.escape(str(item))}</div>')
            lines.append('</div>')

        if sensitive_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: #d9534f; margin-bottom: 4px;">[Potentially Sensitive Metadata ({len(sensitive_entries)} items)]</div>', "sensitive", sensitive_entries, box_open=sensitive_box, marker="⚠️", headline_color=p["sensitive_headline_color"])
        else:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {p["text_secondary"]}; margin-bottom: 4px;">[Potentially Sensitive Metadata]</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {p["text_secondary"]};">No potentially sensitive metadata detected in this file.</div>')

        if meta_entries:
            _group(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">[Extracted Metadata ({len(meta_entries)} fields)]</div>', "meta", meta_entries)

        lines.append('</div>')
        return "\n".join(lines)

    def format_full_scan_evidence_html(self, result, query="", module="All",
                                         view_key=None, collapsed=frozenset(),
                                         expanded_records=frozenset(), palette=None):
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
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))

        visible = filter_footprint(footprint_data, query=query, module=module)
        system = [fd for fd in visible if fd.category == "System"]
        browser = [fd for fd in visible if fd.category == "Browser"]
        file_items = [fd for fd in visible if fd.category == "File & Metadata"]
        other = [fd for fd in visible if fd.category not in ("System", "Browser", "File & Metadata")]

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FULL SCAN EVIDENCE ===</div>'
        ]

        if query or (module and module != "All"):
            lines.append(
                f'<div style="font-size: 12px; color: {p["text_secondary"]}; margin-bottom: 8px;">'
                f'Filter matched <b>{len(visible)}</b> of <b>{total_records}</b> records.</div>'
            )

        if system:
            lines.append(self.format_system_evidence_html(
                system, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records, palette=p))

        if browser:
            lines.append(self.format_browser_evidence_html(
                browser, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records, palette=p))

        if file_items:
            lines.append(self.format_file_evidence_html(
                file_items, view_key=view_key, collapsed=collapsed,
                expanded_records=expanded_records, palette=p))
        elif "no file selected" in (result.message or "").lower():
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {p["text_secondary"]};">File Metadata was skipped because no file was selected. Select a file and run Full Scan again to include it.</div>')

        if other:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: {p["header_color"]}; margin-bottom: 4px;">Additional Evidence:</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for fd in other:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all; color: {p["text_primary"]};"><b>{html.escape(fd.subcategory)}:</b> {html.escape(str(fd.value))} <span style="color: {p["text_muted"]}; font-size: 11px;">[Source: {html.escape(fd.source)}]</span></div>')
            lines.append('</div>')

        if not visible and footprint_data:
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {p["text_secondary"]};">No records match the current filter. Clear the search or choose a different module to see more evidence.</div>')
        elif not footprint_data:
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: {p["text_secondary"]};">No collected evidence was returned by the included modules.</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_public_evidence_html(self, footprint_data, findings, palette=None):
        """Formats Public Lookup evidence while preserving text compatibility."""
        p = palette or (self.get_palette() if hasattr(self, "get_palette") else get_theme_palette(False))
        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">'
        ]

        if footprint_data:
            lines.append(f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FOOTPRINT DATA ===</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for fd in footprint_data:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 4px; word-break: break-all; color: {p["text_primary"]};">Source: {html.escape(fd.source)}<br>Value: {html.escape(str(fd.value))}</div>')
            lines.append('</div>')

        if findings:
            lines.append(f'<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px; color: {p["text_primary"]};">=== FINDINGS ===</div>')
            lines.append(f'<div style="background-color: {p["box_bg"]}; border: 1px solid {p["box_border"]}; border-radius: 4px; padding: 8px; margin-bottom: 10px; color: {p["box_text"]};">')
            for f in findings:
                ev_str = ", ".join(f.evidence) if isinstance(f.evidence, list) else str(f.evidence)
                lines.append(f'<div style="font-size: 12px; margin-bottom: 6px; color: {p["text_primary"]};">[{html.escape(f.severity)}] {html.escape(f.title)}<br>Description: {html.escape(f.description)}<br>Evidence: {html.escape(ev_str)}</div>')
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
            palette=self.get_palette(),
        )

        if hasattr(self, "cache_count_label"):
            self.cache_count_label.setText(self._get_cache_status_text())

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
                palette=self.get_palette(),
            ))

            # Switch to Findings if any exist, otherwise Evidence
            self.full_scan_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        else:
            self.scan_btn.setEnabled(True)
            self.status_label.setText(status_text)
            self.public_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.public_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.public_findings_area.setHtml(findings_html)
            self.results_area.setHtml(self.format_public_evidence_html(
                result.footprint_data, result.findings, palette=self.get_palette()))

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

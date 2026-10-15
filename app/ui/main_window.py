import os
import html
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QTextEdit, QStackedWidget, QListWidget, QTabWidget, QFileDialog
)
from PySide6.QtCore import Qt
from app.ui.workers import ScanWorker

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Footprint Analyzer")
        self.resize(850, 650)

        self.worker = None
        self.selected_file_path = None

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

        self.sys_findings_area = QTextEdit()
        self.sys_findings_area.setReadOnly(True)
        self.sys_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.sys_results_area = QTextEdit()
        self.sys_results_area.setReadOnly(True)
        self.sys_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.sys_sub_tabs.addTab(self.sys_findings_area, "Findings")
        self.sys_sub_tabs.addTab(self.sys_results_area, "Collected Evidence")
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

        self.browser_findings_area = QTextEdit()
        self.browser_findings_area.setReadOnly(True)
        self.browser_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.browser_results_area = QTextEdit()
        self.browser_results_area.setReadOnly(True)
        self.browser_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.browser_sub_tabs.addTab(self.browser_findings_area, "Findings")
        self.browser_sub_tabs.addTab(self.browser_results_area, "Collected Evidence")
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

        self.file_findings_area = QTextEdit()
        self.file_findings_area.setReadOnly(True)
        self.file_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.file_results_area = QTextEdit()
        self.file_results_area.setReadOnly(True)
        self.file_results_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

        self.file_sub_tabs.addTab(self.file_findings_area, "Findings")
        self.file_sub_tabs.addTab(self.file_results_area, "Collected Evidence")
        file_layout.addWidget(self.file_sub_tabs)

        self.my_footprint_tabs.addTab(file_tab, "File & Metadata Footprint")

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

        self.public_findings_area = QTextEdit()
        self.public_findings_area.setReadOnly(True)
        self.public_findings_area.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

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

    # --------------------------------------------------------
    # HTML FORMATTERS FOR FINDINGS AND COLLECTED EVIDENCE
    # --------------------------------------------------------

    def format_findings_html(self, findings, evidence_count=0):
        """Formats the list of Finding objects into structured, restrained HTML cards with scan summary."""
        total_findings = len(findings) if findings else 0
        concerns_count = sum(1 for f in findings if (getattr(f, "category", "") or "") == "Concern") if findings else 0
        observations_count = total_findings - concerns_count

        # Build Scan Summary Header Banner
        summary_html = f"""
        <div style="font-family: sans-serif; margin-bottom: 12px; padding: 8px 12px; background-color: #f8f9fa; border: 1px solid #e1e4e8; border-radius: 6px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="font-size: 12px; color: #333;">
                <tr>
                    <td style="font-weight: bold; color: #24292e; padding-right: 12px;">
                        SCAN SUMMARY:
                    </td>
                    <td style="padding: 2px 6px;">
                        <b>Total Findings:</b> <span style="background-color: #e1e4e8; color: #24292e; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{total_findings}</span>
                    </td>
                    <td style="padding: 2px 6px;">
                        <b>Concerns:</b> <span style="background-color: #ffeef0; color: #cb2431; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{concerns_count}</span>
                    </td>
                    <td style="padding: 2px 6px;">
                        <b>Observations:</b> <span style="background-color: #f1f8ff; color: #0366d6; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{observations_count}</span>
                    </td>
                    <td style="padding: 2px 6px;" align="right">
                        <b>Evidence Items:</b> <span style="background-color: #f6f8fa; color: #444d56; font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{evidence_count}</span>
                    </td>
                </tr>
            </table>
        </div>
        """

        if not findings:
            return f"""
            <div style="font-family: sans-serif; padding: 4px;">
                {summary_html}
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

        for f in findings:
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

            evidence_val = f.evidence
            if isinstance(evidence_val, list):
                evidence_text = ", ".join(str(e) for e in evidence_val)
            else:
                evidence_text = str(evidence_val)

            rule_html = f'<span style="font-size: 11px; color: #6a737d; font-family: monospace;">Rule: {html.escape(rule_id)}</span>' if rule_id else ""
            limitations_html = (
                f'<div style="font-size: 11px; color: #586069; font-style: italic; margin-top: 5px; padding-top: 4px; border-top: 1px dotted #e1e4e8;">'
                f'<b>Scope Limitation:</b> {html.escape(limitations)}</div>'
            ) if limitations else ""

            card = f"""
            <div style="border: 1px solid #e1e4e8; border-left: 4px solid {card_border}; border-radius: 4px; background-color: {card_bg}; padding: 8px 10px; margin-bottom: 8px;">
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
                <div style="font-size: 12px; color: #24292e; line-height: 1.4; margin-bottom: 5px;">
                    {html.escape(f.description)}
                </div>
                <div style="background-color: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 3px; padding: 4px 8px; font-family: monospace; font-size: 11px; color: #24292e; word-break: break-all;">
                    <b>Evidence:</b> {html.escape(evidence_text)}
                </div>
                {limitations_html}
            </div>
            """
            cards.append(card)

        cards.append('</div>')
        return "\n".join(cards)

    def format_system_evidence_html(self, footprint_data):
        """Formats System Footprint collected evidence with structured sections and word-wrap."""
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
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Startup Applications ({len(startups)} detected):</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for app in startups:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;">• {html.escape(str(app.value))} <span style="color: #888; font-size: 11px;">[Source: {html.escape(app.source)}]</span></div>')
            lines.append('</div>')

        if installed_apps:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Installed Applications ({len(installed_apps)} detected):</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for app in installed_apps:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 2px; word-break: break-all;">• {html.escape(str(app.value))} <span style="color: #888; font-size: 11px;">[Source: {html.escape(app.source)}]</span></div>')
            lines.append('</div>')

        if processes:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Running Processes ({len(processes)} detected):</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for p in processes:
                lines.append(f'<div style="font-size: 11px; font-family: monospace; margin-bottom: 2px; word-break: break-all;">{html.escape(str(p.value))}</div>')
            lines.append('</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_browser_evidence_html(self, footprint_data):
        """Formats Browser Footprint collected evidence with structured sections and word-wrap."""
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

        lines = [
            '<div style="font-family: sans-serif; padding: 4px;">',
            '<div style="font-weight: bold; font-size: 13px; margin-bottom: 8px;">=== FOOTPRINT DATA ===</div>'
        ]

        if browsers:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Detected Browsers ({len(browsers)}):</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for b in browsers:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 4px; word-break: break-all;"><b>{html.escape(str(b.value))}</b> <span style="color: #888; font-size: 11px;">[Source: {html.escape(b.source)}]</span></div>')
            lines.append('</div>')

        if extensions:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Installed Extensions ({len(extensions)}):</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for ext in extensions:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; word-break: break-all;">• {html.escape(str(ext.value))} <span style="color: #888; font-size: 11px;">[Source: {html.escape(ext.source)}]</span></div>')
            lines.append('</div>')

        if coverage:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">Scan Coverage Notes:</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for c in coverage:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px;">{html.escape(str(c.value))}</div>')
            lines.append('</div>')

        lines.append('</div>')
        return "\n".join(lines)

    def format_file_evidence_html(self, footprint_data):
        """Formats File & Metadata collected evidence."""
        file_details = []
        meta_entries = []
        sensitive_entries = []

        for fd in footprint_data:
            if fd.subcategory in ("File Information", "File Path", "File Timestamps"):
                file_details.append(fd.value)
            elif fd.subcategory == "Embedded Metadata":
                meta_entries.append(fd.value)
            elif fd.subcategory == "Potentially Sensitive":
                sensitive_entries.append(fd.value)

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
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #d9534f; margin-bottom: 4px;">[Potentially Sensitive Metadata ({len(sensitive_entries)} items)]</div>')
            lines.append('<div style="background-color: #fff8f8; border: 1px solid #f5c6cb; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for item in sensitive_entries:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 3px; color: #721c24; word-break: break-all;">⚠️ {html.escape(str(item))}</div>')
            lines.append('</div>')
        else:
            lines.append('<div style="font-weight: bold; font-size: 12px; color: #555; margin-bottom: 4px;">[Potentially Sensitive Metadata]</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px; font-size: 12px; color: #666;">No potentially sensitive metadata detected in this file.</div>')

        if meta_entries:
            lines.append(f'<div style="font-weight: bold; font-size: 12px; color: #1e3799; margin-bottom: 4px;">[Extracted Metadata ({len(meta_entries)} fields)]</div>')
            lines.append('<div style="background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 8px; margin-bottom: 10px;">')
            for item in meta_entries:
                lines.append(f'<div style="font-size: 12px; margin-bottom: 2px; font-family: monospace; word-break: break-all;">• {html.escape(str(item))}</div>')
            lines.append('</div>')

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

        status_text = f"Status: {result.status} | Message: {result.message}"
        findings_count = len(result.findings)
        evidence_count = len(result.footprint_data)

        # Generate shared formatted findings HTML
        findings_html = self.format_findings_html(result.findings, evidence_count=evidence_count)

        if is_sys:
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(status_text)
            self.sys_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.sys_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.sys_findings_area.setHtml(findings_html)
            self.sys_results_area.setHtml(self.format_system_evidence_html(result.footprint_data))

            # Switch to Findings if any exist, otherwise Evidence
            self.sys_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        elif is_browser:
            self.browser_scan_btn.setEnabled(True)
            self.browser_status_label.setText(status_text)
            self.browser_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.browser_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.browser_findings_area.setHtml(findings_html)
            self.browser_results_area.setHtml(self.format_browser_evidence_html(result.footprint_data))

            self.browser_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

        elif is_file:
            self.file_select_btn.setEnabled(True)
            self.file_analyze_btn.setEnabled(True)
            self.file_status_label.setText(status_text)
            self.file_sub_tabs.setTabText(0, f"Findings ({findings_count})")
            self.file_sub_tabs.setTabText(1, f"Collected Evidence ({evidence_count})")

            self.file_findings_area.setHtml(findings_html)
            self.file_results_area.setHtml(self.format_file_evidence_html(result.footprint_data))

            self.file_sub_tabs.setCurrentIndex(0 if findings_count > 0 else 1)

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

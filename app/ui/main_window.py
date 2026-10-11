import os
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
        self.resize(800, 600)
        
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

        self.sidebar.setCurrentRow(2) # Default to Public Lookup

    def init_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Welcome to Digital Footprint Analyzer</h2>"))
        layout.addStretch()
        self.pages.addWidget(page)

    def init_my_footprint_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>My Footprint</h2>"))
        layout.addWidget(QLabel("Analyze information from your own system and files."))

        # Sub-category tabs: System Footprint and File & Metadata Footprint
        self.my_footprint_tabs = QTabWidget()

        # Tab 1: System Footprint
        sys_tab = QWidget()
        sys_layout = QVBoxLayout(sys_tab)
        
        self.sys_scan_btn = QPushButton("Scan System Footprint")
        self.sys_scan_btn.clicked.connect(self.start_system_scan)
        sys_layout.addWidget(self.sys_scan_btn)

        self.sys_status_label = QLabel("")
        sys_layout.addWidget(self.sys_status_label)

        self.sys_results_area = QTextEdit()
        self.sys_results_area.setReadOnly(True)
        sys_layout.addWidget(self.sys_results_area)

        self.my_footprint_tabs.addTab(sys_tab, "System Footprint")

        # Tab 2: File & Metadata Footprint
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
        file_layout.addWidget(self.file_status_label)

        self.file_results_area = QTextEdit()
        self.file_results_area.setReadOnly(True)
        file_layout.addWidget(self.file_results_area)

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

        # Status and Results
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        layout.addWidget(self.results_area)
        
        self.pages.addWidget(page)

    def init_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("<h2>Settings</h2>"))
        layout.addStretch()
        self.pages.addWidget(page)

    def change_page(self, index):
        self.pages.setCurrentIndex(index)

    def start_system_scan(self):
        if self.worker and self.worker.isRunning():
            return
            
        self.sys_scan_btn.setEnabled(False)
        self.sys_status_label.setText("Scanning... Please wait, this may take a while.")
        self.sys_results_area.clear()

        self.worker = ScanWorker("System", "")
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
        self.status_label.setText("Scanning... Please wait, this may take a while.")
        self.results_area.clear()

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
            self.file_results_area.clear()
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
        self.file_results_area.clear()

        self.worker = ScanWorker("File & Metadata", file_path)
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_complete(self, result):
        is_sys = (result.scan_type == "System")
        is_file = (result.scan_type == "File & Metadata")
        
        if is_sys:
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(f"Status: {result.status} | Message: {result.message}")
        elif is_file:
            self.file_select_btn.setEnabled(True)
            self.file_analyze_btn.setEnabled(True)
            self.file_status_label.setText(f"Status: {result.status} | Message: {result.message}")
        else:
            self.scan_btn.setEnabled(True)
            self.status_label.setText(f"Status: {result.status} | Message: {result.message}")
        
        # Format output
        output_text = []
        if is_file:
            file_output = ["=== FILE & METADATA FOOTPRINT ==="]
            file_details = []
            meta_entries = []
            sensitive_entries = []

            for fd in result.footprint_data:
                if fd.subcategory in ("File Information", "File Path", "File Timestamps"):
                    file_details.append(fd.value)
                elif fd.subcategory == "Embedded Metadata":
                    meta_entries.append(fd.value)
                elif fd.subcategory == "Potentially Sensitive":
                    sensitive_entries.append(fd.value)

            if file_details:
                file_output.append("\n[File Details]")
                for item in file_details:
                    file_output.append(f"  • {item}")

            if meta_entries:
                file_output.append(f"\n[Extracted Metadata ({len(meta_entries)} fields)]")
                for item in meta_entries:
                    file_output.append(f"  • {item}")

            if sensitive_entries:
                file_output.append(f"\n[Potentially Sensitive Metadata ({len(sensitive_entries)} items)]")
                for item in sensitive_entries:
                    file_output.append(f"  ⚠️  {item}")
            else:
                file_output.append("\n[Potentially Sensitive Metadata]")
                file_output.append("  No potentially sensitive metadata detected in this file.")

            self.file_results_area.setText("\n".join(file_output))
            return

        if result.footprint_data:
            output_text.append("=== FOOTPRINT DATA ===")
            if result.scan_type == "System":
                output_text.append("System Footprint:")
                system_info = []
                installed_apps = []
                for fd in result.footprint_data:
                    if fd.subcategory == "Installed Applications":
                        installed_apps.append(fd)
                    else:
                        system_info.append(fd)
                
                for fd in system_info:
                    output_text.append(f"  {fd.subcategory}: {fd.value}  [Source: {fd.source}]")
                
                if installed_apps:
                    output_text.append(f"\n  Installed Applications ({len(installed_apps)} detected):")
                    for app in installed_apps:
                        output_text.append(f"    • {app.value}  [Source: {app.source}]")
            else:
                for fd in result.footprint_data:
                    output_text.append(f"Source: {fd.source}\nValue: {fd.value}\n")
                
        if result.findings:
            output_text.append("=== FINDINGS ===")
            for f in result.findings:
                evidence_text = ", ".join(f.evidence) if isinstance(f.evidence, list) else str(f.evidence)
                output_text.append(f"[{f.severity}] {f.title}\nDescription: {f.description}\nEvidence: {evidence_text}\n")
        if is_sys:
            self.sys_results_area.setText("\n".join(output_text))
        else:
            self.results_area.setText("\n".join(output_text))

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


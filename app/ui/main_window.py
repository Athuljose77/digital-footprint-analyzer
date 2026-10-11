from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QLineEdit, QComboBox, 
    QTextEdit, QStackedWidget, QListWidget
)
from PySide6.QtCore import Qt
from app.ui.workers import ScanWorker

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Footprint Analyzer")
        self.resize(800, 600)
        
        self.worker = None

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
        layout.addWidget(QLabel("Analyze information from your own system."))
        
        self.sys_scan_btn = QPushButton("System Footprint")
        self.sys_scan_btn.clicked.connect(self.start_system_scan)
        layout.addWidget(self.sys_scan_btn)

        self.sys_status_label = QLabel("")
        layout.addWidget(self.sys_status_label)
        
        self.sys_results_area = QTextEdit()
        self.sys_results_area.setReadOnly(True)
        layout.addWidget(self.sys_results_area)

        # --- Browser Footprint Section ---
        self.browser_scan_btn = QPushButton("Browser Footprint")
        self.browser_scan_btn.clicked.connect(self.start_browser_scan)
        layout.addWidget(self.browser_scan_btn)

        self.browser_status_label = QLabel("")
        layout.addWidget(self.browser_status_label)

        self.browser_results_area = QTextEdit()
        self.browser_results_area.setReadOnly(True)
        layout.addWidget(self.browser_results_area)

        layout.addStretch()
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

    def start_browser_scan(self):
        if self.worker and self.worker.isRunning():
            return

        self.browser_scan_btn.setEnabled(False)
        self.browser_status_label.setText("Scanning browsers... Please wait.")
        self.browser_results_area.clear()

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
        self.status_label.setText("Scanning... Please wait, this may take a while.")
        self.results_area.clear()

        self.worker = ScanWorker(scan_type, target)
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_complete(self, result):
        is_sys = (result.scan_type == "System")
        is_browser = (result.scan_type == "Browser")
        
        if is_sys:
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(f"Status: {result.status} | Message: {result.message}")
        elif is_browser:
            self.browser_scan_btn.setEnabled(True)
            self.browser_status_label.setText(f"Status: {result.status} | Message: {result.message}")
        else:
            self.scan_btn.setEnabled(True)
            self.status_label.setText(f"Status: {result.status} | Message: {result.message}")
        
        # Format output
        output_text = []
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
        elif is_browser:
            self.browser_results_area.setText("\n".join(output_text))
        else:
            self.results_area.setText("\n".join(output_text))

    def on_scan_error(self, err_msg):
        if hasattr(self, 'scan_btn'):
            self.scan_btn.setEnabled(True)
            self.status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'sys_scan_btn'):
            self.sys_scan_btn.setEnabled(True)
            self.sys_status_label.setText(f"Error: {err_msg}")
        if hasattr(self, 'browser_scan_btn'):
            self.browser_scan_btn.setEnabled(True)
            self.browser_status_label.setText(f"Error: {err_msg}")

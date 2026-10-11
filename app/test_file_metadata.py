import os
import sys
import time
import struct
import zlib
import tempfile
import asyncio
from unittest.mock import patch, AsyncMock

# Ensure the app can import modules from the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.file_metadata_service import (
    analyze_file,
    check_file_metadata,
    detect_file_type,
    format_file_size,
    identify_sensitive_metadata
)
from app.core.scan_controller import run_file_metadata_scan, run_system_scan, run_email_scan, run_username_scan
from PySide6.QtWidgets import QApplication
from app.ui.main_window import MainWindow


# ============================================================
# HELPER GENERATORS FOR TEST IMAGES
# ============================================================

def make_test_jpeg_with_exif(include_gps=True, include_camera=True) -> bytes:
    """Generate in-memory JPEG with customized EXIF data."""
    # TIFF Little-Endian Header
    tiff = bytearray(b"II\x2a\x00\x08\x00\x00\x00")
    
    entries = []
    if include_camera:
        # Make: tag 0x010F, ASCII, len 6
        entries.append((0x010F, 2, 6, b"Canon\x00"))
        # Model: tag 0x0110, ASCII, len 7
        entries.append((0x0110, 2, 7, b"EOS-R5\x00"))
        # Software: tag 0x0131, ASCII, len 10
        entries.append((0x0131, 2, 10, b"Firmware1\x00"))
        # Artist: tag 0x013B, ASCII, len 8
        entries.append((0x013B, 2, 8, b"Photog1\x00"))

    # If GPS, we add GPS Info Offset pointer
    gps_offset = 0
    gps_sub = bytearray()
    if include_gps:
        # GPS SubIFD:
        # Latitude: 37° 46' 29.0" N
        # Longitude: 122° 25' 10.0" W
        # Altitude: 15 m
        gps_sub += struct.pack("<H", 4)
        gps_sub += struct.pack("<HHI", 0x0001, 2, 2) + b"N\x00\x00\x00"
        gps_sub += struct.pack("<HHI", 0x0002, 5, 3) + struct.pack("<I", 0)  # offset placeholder
        gps_sub += struct.pack("<HHI", 0x0003, 2, 2) + b"W\x00\x00\x00"
        gps_sub += struct.pack("<HHI", 0x0004, 5, 3) + struct.pack("<I", 0)  # offset placeholder
        gps_sub += struct.pack("<I", 0)

    # Calculate layout
    num_ifd0 = len(entries) + (1 if include_gps else 0)
    ifd0_header = struct.pack("<H", num_ifd0)
    
    offset_cursor = 8 + 2 + (num_ifd0 * 12) + 4
    ifd0_entries_bytes = bytearray()
    payload_values = bytearray()

    for tag, typ, count, val_bytes in entries:
        val_offset = offset_cursor + len(payload_values)
        ifd0_entries_bytes += struct.pack("<HHI", tag, typ, count) + struct.pack("<I", val_offset)
        payload_values += val_bytes

    if include_gps:
        gps_offset_val = offset_cursor + len(payload_values)
        ifd0_entries_bytes += struct.pack("<HHI", 0x8825, 4, 1) + struct.pack("<I", gps_offset_val)
        
        # Now fix GPS rationals offsets
        gps_rationals_offset = gps_offset_val + 2 + (4 * 12) + 4
        # Latitude rational offset
        gps_sub[2 + 12 + 8: 2 + 12 + 12] = struct.pack("<I", gps_rationals_offset)
        # Longitude rational offset
        gps_sub[2 + (3 * 12) + 8: 2 + (3 * 12) + 12] = struct.pack("<I", gps_rationals_offset + 24)
        
        gps_rationals = struct.pack("<IIIIII", 37, 1, 46, 1, 29, 1) + struct.pack("<IIIIII", 122, 1, 25, 1, 10, 1)
        payload_values += gps_sub + gps_rationals

    tiff += ifd0_header + ifd0_entries_bytes + struct.pack("<I", 0) + payload_values
    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_len = len(app1_payload) + 2
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", app1_len) + app1_payload + b"\xff\xd9"


def make_test_png(text_dict=None) -> bytes:
    """Generate in-memory PNG with text metadata chunks."""
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    ihdr_data = struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)
    crc = zlib.crc32(b"IHDR" + ihdr_data)
    png += struct.pack(">I4s", len(ihdr_data), b"IHDR") + ihdr_data + struct.pack(">I", crc)

    if text_dict:
        for k, v in text_dict.items():
            chunk_data = k.encode("latin-1") + b"\x00" + v.encode("latin-1")
            c = zlib.crc32(b"tEXt" + chunk_data)
            png += struct.pack(">I4s", len(chunk_data), b"tEXt") + chunk_data + struct.pack(">I", c)

    # Add tIME chunk (Year 2024, May 15, 12:30:45)
    time_data = struct.pack(">HBBBBB", 2024, 5, 15, 12, 30, 45)
    time_crc = zlib.crc32(b"tIME" + time_data)
    png += struct.pack(">I4s", len(time_data), b"tIME") + time_data + struct.pack(">I", time_crc)

    iend_crc = zlib.crc32(b"IEND")
    png += struct.pack(">I4s", 0, b"IEND") + struct.pack(">I", iend_crc)
    return bytes(png)


# ============================================================
# TEST SUITE
# ============================================================

def test_1_and_8_jpeg_with_camera_metadata():
    print("--- Test 1 & 8: Valid JPEG with Camera Metadata ---")
    data = make_test_jpeg_with_exif(include_gps=False, include_camera=True)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        res = analyze_file(path)
        assert res["status"] == "SUCCESS"
        assert res["results"]["is_supported"] is True
        assert res["results"]["metadata_found"] is True
        meta = res["results"]["metadata"]
        assert meta.get("Camera Make") == "Canon"
        assert meta.get("Camera Model") == "EOS-R5"
        assert meta.get("Artist / Author") == "Photog1"
        assert meta.get("Software") == "Firmware1"

        sensitive = res["results"]["potentially_sensitive"]
        categories = {s["category"] for s in sensitive}
        assert "Device & Hardware Identification" in categories
        assert "Personal Identification" in categories
        assert "Software & Environment" in categories
        print("Test 1 & 8 passed.")
    finally:
        os.remove(path)


def test_2_jpeg_with_no_metadata():
    print("--- Test 2: JPEG with No Metadata ---")
    data = b"\xff\xd8\xff\xd9"
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        res = analyze_file(path)
        assert res["status"] == "SUCCESS"
        assert res["results"]["is_supported"] is True
        assert res["results"]["metadata_found"] is False
        assert len(res["results"]["potentially_sensitive"]) == 0
        assert "No embedded metadata found" in res["message"]
        print("Test 2 passed.")
    finally:
        os.remove(path)


def test_3_png_metadata():
    print("--- Test 3: PNG with Text & Time Metadata ---")
    data = make_test_png({"Author": "Alice Designer", "Software": "Affinity Photo"})
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        res = analyze_file(path)
        assert res["status"] == "SUCCESS"
        assert res["results"]["is_supported"] is True
        assert res["results"]["metadata_found"] is True
        meta = res["results"]["metadata"]
        assert meta.get("PNG Author") == "Alice Designer"
        assert meta.get("PNG Software") == "Affinity Photo"
        assert "PNG Timestamp (tIME)" in meta
        sensitive = res["results"]["potentially_sensitive"]
        fields = {s["field"] for s in sensitive}
        assert "PNG Author" in fields
        assert "PNG Software" in fields
        print("Test 3 passed.")
    finally:
        os.remove(path)


def test_4_unsupported_file():
    print("--- Test 4: Unsupported File Type ---")
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"plain text document\n")
        path = f.name
    try:
        res = analyze_file(path)
        assert res["status"] == "SUCCESS"
        assert res["results"]["is_supported"] is False
        assert res["results"]["metadata_found"] is False
        assert "unsupported for deep embedded metadata extraction" in res["message"]
        print("Test 4 passed.")
    finally:
        os.remove(path)


def test_5_missing_file():
    print("--- Test 5: Missing File Handling ---")
    res = analyze_file("/path/to/definitely/nonexistent_file_12345.jpg")
    assert res["status"] == "ERROR"
    assert "does not exist" in res["message"]
    print("Test 5 passed.")


def test_6_unreadable_file():
    print("--- Test 6: Unreadable File Permission Handling ---")
    with patch("os.path.exists", return_value=True), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=False):
        res = analyze_file("dummy.jpg")
        assert res["status"] == "ERROR"
        assert "Permission denied" in res["message"] or "Unable to read" in res["message"]
        print("Test 6 passed.")


def test_7_metadata_with_gps():
    print("--- Test 7: Metadata with GPS Location ---")
    data = make_test_jpeg_with_exif(include_gps=True, include_camera=True)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        res = analyze_file(path)
        assert res["status"] == "SUCCESS"
        meta = res["results"]["metadata"]
        assert "GPS Coordinates" in meta
        assert "37°46'29.00\"N" in meta["GPS Coordinates"]
        assert "122°25'10.00\"W" in meta["GPS Coordinates"]
        
        sensitive = res["results"]["potentially_sensitive"]
        gps_items = [s for s in sensitive if s["category"] == "Location & GPS"]
        assert len(gps_items) > 0
        assert "exact geographic location" in gps_items[0]["description"].lower()
        print("Test 7 passed.")
    finally:
        os.remove(path)


async def test_controller_file_metadata_scan():
    print("--- Testing Scan Controller: run_file_metadata_scan ---")
    data = make_test_jpeg_with_exif(include_gps=True, include_camera=True)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        scan_res = await run_file_metadata_scan(path)
        assert scan_res.status == "COMPLETED"
        assert scan_res.scan_type == "File & Metadata"
        assert scan_res.analysis_mode == "My Footprint"
        assert len(scan_res.footprint_data) > 0
        
        subcats = {fd.subcategory for fd in scan_res.footprint_data}
        assert "File Information" in subcats
        assert "File Path" in subcats
        assert "Embedded Metadata" in subcats
        assert "Potentially Sensitive" in subcats
        print("Scan Controller test passed.")
    finally:
        os.remove(path)


def test_ui_and_regressions():
    print("--- Testing UI Navigation, Scan Execution, and Regressions ---")
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    window = MainWindow()

    def wait_for_worker():
        if window.worker:
            while not window.worker.isFinished():
                app.processEvents()
                time.sleep(0.02)
            window.worker.wait()
            app.processEvents()

    # 13. UI Navigation Test
    assert window.sidebar.count() == 4
    window.sidebar.setCurrentRow(0) # Home
    assert window.pages.currentIndex() == 0
    window.sidebar.setCurrentRow(1) # My Footprint
    assert window.pages.currentIndex() == 1
    assert window.my_footprint_tabs.count() >= 2
    window.sidebar.setCurrentRow(2) # Public Lookup
    assert window.pages.currentIndex() == 2
    print("Test 13: UI navigation passed.")

    # 9. User File Selection Cancellation / No File Selected Test
    window.sidebar.setCurrentRow(1)
    for idx in range(window.my_footprint_tabs.count()):
        if "File" in window.my_footprint_tabs.tabText(idx):
            window.my_footprint_tabs.setCurrentIndex(idx)
            break
    window.selected_file_path = None
    window.start_file_analysis()
    assert "No file selected" in window.file_status_label.text()
    assert window.worker is None
    print("Test 9: User cancellation / no file handling passed.")

    # Test File Analysis via UI with synthesized JPEG
    data = make_test_jpeg_with_exif(include_gps=True, include_camera=True)
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(data)
        test_img_path = f.name

    try:
        window.selected_file_path = test_img_path
        window.selected_file_label.setText(os.path.basename(test_img_path))
        window.file_analyze_btn.setEnabled(True)

        window.start_file_analysis()
        worker1 = window.worker
        assert worker1 is not None and worker1.isRunning()

        # 14. Repeated Scan Protection
        window.start_file_analysis()
        worker2 = window.worker
        assert worker1 is worker2, "Repeated scan protection failed!"
        print("Test 14: Repeated scan protection passed.")

        wait_for_worker()
        results_text = window.file_results_area.toPlainText()
        assert "=== FILE & METADATA FOOTPRINT ===" in results_text
        assert "Camera Make: Canon" in results_text
        assert "GPS Coordinates" in results_text
        assert "Potentially Sensitive Metadata" in results_text
        print("UI File & Metadata analysis output verified.")

    finally:
        os.remove(test_img_path)

    # 10. Existing System Footprint Regression
    print("Verifying System Footprint regression...")
    window.my_footprint_tabs.setCurrentIndex(0) # System Footprint
    window.sys_scan_btn.click()
    wait_for_worker()
    sys_text = window.sys_results_area.toPlainText()
    assert "System Footprint:" in sys_text
    print("Test 10: Existing System Footprint regression passed.")

    # 11 & 12. Email and Username Regression Check
    print("Verifying Public Lookup regressions...")
    window.sidebar.setCurrentRow(2)
    with patch("app.core.scan_controller.check_email", new_callable=AsyncMock) as mock_email:
        mock_email.return_value = {"status": "SUCCESS", "breaches": []}
        window.scan_type_combo.setCurrentText("Email")
        window.target_input.setText("test@example.com")
        window.scan_btn.click()
        wait_for_worker()
        assert "Status: COMPLETED" in window.status_label.text()
    print("Test 11: Email regression passed.")

    with patch("app.core.scan_controller.check_username", new_callable=AsyncMock) as mock_user:
        mock_user.return_value = {"status": "NOT_FOUND"}
        window.scan_type_combo.setCurrentText("Username")
        window.target_input.setText("testuser")
        window.scan_btn.click()
        wait_for_worker()
        assert "Status: COMPLETED" in window.status_label.text()
    print("Test 12: Username regression passed.")

    app.quit()
    print("All UI and regression tests passed.")


def main():
    test_1_and_8_jpeg_with_camera_metadata()
    test_2_jpeg_with_no_metadata()
    test_3_png_metadata()
    test_4_unsupported_file()
    test_5_missing_file()
    test_6_unreadable_file()
    test_7_metadata_with_gps()
    asyncio.run(test_controller_file_metadata_scan())
    test_ui_and_regressions()
    print("\n============================================================")
    print("ALL FILE & METADATA FOOTPRINT V1 TESTS COMPLETED SUCCESSFULLY!")
    print("============================================================")


if __name__ == "__main__":
    main()

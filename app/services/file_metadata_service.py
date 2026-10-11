import os
import struct
import zlib
import mimetypes
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# ============================================================
# EXIF TAG DICTIONARIES
# ============================================================

TIFF_TAGS = {
    0x010E: "Image Description",
    0x010F: "Camera Make",
    0x0110: "Camera Model",
    0x0112: "Orientation",
    0x011A: "X Resolution",
    0x011B: "Y Resolution",
    0x0128: "Resolution Unit",
    0x0131: "Software",
    0x0132: "Date & Time Modified",
    0x013B: "Artist / Author",
    0x8298: "Copyright",
    0x8769: "Exif Offset",
    0x8825: "GPS Info Offset",
}

EXIF_SUBIFD_TAGS = {
    0x829A: "Exposure Time",
    0x829D: "F-Number",
    0x8822: "Exposure Program",
    0x8827: "ISO Speed",
    0x9000: "Exif Version",
    0x9003: "Date & Time Original",
    0x9004: "Date & Time Digitized",
    0x9010: "Offset Time",
    0x9011: "Offset Time Original",
    0x9201: "Shutter Speed",
    0x9202: "Aperture Value",
    0x9204: "Exposure Bias",
    0x9207: "Metering Mode",
    0x9208: "Light Source",
    0x9209: "Flash",
    0x920A: "Focal Length",
    0x9286: "User Comment",
    0x9290: "SubSec Time",
    0x9291: "SubSec Time Original",
    0x9292: "SubSec Time Digitized",
    0xA002: "Exif Image Width",
    0xA003: "Exif Image Height",
    0xA405: "Focal Length In 35mm",
    0xA420: "Image Unique ID",
    0xA430: "Camera Owner Name",
    0xA431: "Body Serial Number",
    0xA432: "Lens Specification",
    0xA433: "Lens Make",
    0xA434: "Lens Model",
    0xA435: "Lens Serial Number",
}

GPS_TAGS = {
    0x0000: "GPS Version ID",
    0x0001: "GPS Latitude Ref",
    0x0002: "GPS Latitude",
    0x0003: "GPS Longitude Ref",
    0x0004: "GPS Longitude",
    0x0005: "GPS Altitude Ref",
    0x0006: "GPS Altitude",
    0x0007: "GPS Time Stamp",
    0x0008: "GPS Satellites",
    0x0009: "GPS Status",
    0x000A: "GPS Measure Mode",
    0x000B: "GPS DOP",
    0x000C: "GPS Speed Ref",
    0x000D: "GPS Speed",
    0x000E: "GPS Track Ref",
    0x000F: "GPS Track",
    0x0010: "GPS Image Direction Ref",
    0x0011: "GPS Image Direction",
    0x0012: "GPS Map Datum",
    0x001D: "GPS Date Stamp",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def format_file_size(size_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def detect_file_type(file_path: str, header_bytes: bytes) -> Tuple[str, str, bool]:
    """
    Detect file format from magic bytes and extension.
    Returns (Type Description, MIME Type, Is Supported for deep metadata in v1).
    """
    if header_bytes.startswith(b"\xff\xd8\xff"):
        return "JPEG Image", "image/jpeg", True
    if header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image", "image/png", True
    if header_bytes.startswith(b"GIF87a") or header_bytes.startswith(b"GIF89a"):
        return "GIF Image", "image/gif", False
    if header_bytes.startswith(b"%PDF"):
        return "PDF Document", "application/pdf", False
    if header_bytes.startswith(b"RIFF") and len(header_bytes) >= 12 and header_bytes[8:12] == b"WEBP":
        return "WebP Image", "image/webp", False

    # Fallback to extension
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext in [".jpg", ".jpeg"]:
        return "JPEG Image", "image/jpeg", True
    if ext == ".png":
        return "PNG Image", "image/png", True

    mime, _ = mimetypes.guess_type(file_path)
    mime_str = mime if mime else "application/octet-stream"
    type_name = f"{ext.upper()[1:]} File" if ext else "Binary File"
    return type_name, mime_str, False


# ============================================================
# TIFF / EXIF PARSER (PURE PYTHON STANDARD LIBRARY)
# ============================================================

def _parse_tiff_entry(endian: str, entry_bytes: bytes, tiff_bytes: bytes) -> Tuple[Optional[int], Any]:
    """Parse a single 12-byte TIFF IFD entry."""
    if len(entry_bytes) < 12:
        return None, None
    tag, typ, count, val_or_offset = struct.unpack(endian + "HHI4s", entry_bytes)

    # 1 = BYTE, 2 = ASCII, 3 = SHORT, 4 = LONG, 5 = RATIONAL,
    # 7 = UNDEFINED, 9 = SLONG, 10 = SRATIONAL
    if typ == 2:  # ASCII
        if count <= 4:
            raw_str = val_or_offset[:count]
        else:
            offset, = struct.unpack(endian + "I", val_or_offset)
            if offset + count <= len(tiff_bytes):
                raw_str = tiff_bytes[offset:offset + count]
            else:
                raw_str = b""
        if b"\x00" in raw_str:
            raw_str = raw_str.split(b"\x00", 1)[0]
        return tag, raw_str.decode("utf-8", errors="replace").strip()

    elif typ == 3:  # SHORT (unsigned 16-bit)
        if count == 1:
            val, = struct.unpack(endian + "H", val_or_offset[:2])
            return tag, val
        elif count == 2:
            val = struct.unpack(endian + "HH", val_or_offset[:4])
            return tag, list(val)
        else:
            offset, = struct.unpack(endian + "I", val_or_offset)
            if offset + (count * 2) <= len(tiff_bytes):
                vals = struct.unpack(endian + f"{count}H", tiff_bytes[offset:offset + (count * 2)])
                return tag, list(vals)

    elif typ == 4:  # LONG (unsigned 32-bit)
        if count == 1:
            val, = struct.unpack(endian + "I", val_or_offset)
            return tag, val
        else:
            offset, = struct.unpack(endian + "I", val_or_offset)
            if offset + (count * 4) <= len(tiff_bytes):
                vals = struct.unpack(endian + f"{count}I", tiff_bytes[offset:offset + (count * 4)])
                return tag, list(vals)

    elif typ == 5:  # RATIONAL (unsigned num / den, 8 bytes each)
        offset, = struct.unpack(endian + "I", val_or_offset)
        if offset + (count * 8) <= len(tiff_bytes):
            rationals = []
            for i in range(count):
                pos = offset + (i * 8)
                num, den = struct.unpack(endian + "II", tiff_bytes[pos:pos + 8])
                val = (num / den) if den != 0 else 0.0
                rationals.append(val)
            return tag, rationals[0] if count == 1 else rationals

    elif typ == 10:  # SRATIONAL (signed num / den, 8 bytes each)
        offset, = struct.unpack(endian + "I", val_or_offset)
        if offset + (count * 8) <= len(tiff_bytes):
            rationals = []
            for i in range(count):
                pos = offset + (i * 8)
                num, den = struct.unpack(endian + "ii", tiff_bytes[pos:pos + 8])
                val = (num / den) if den != 0 else 0.0
                rationals.append(val)
            return tag, rationals[0] if count == 1 else rationals

    elif typ == 1:  # BYTE
        if count <= 4:
            return tag, list(val_or_offset[:count])
        else:
            offset, = struct.unpack(endian + "I", val_or_offset)
            if offset + count <= len(tiff_bytes):
                return tag, list(tiff_bytes[offset:offset + count])

    elif typ == 7:  # UNDEFINED
        if count <= 4:
            raw = val_or_offset[:count]
        else:
            offset, = struct.unpack(endian + "I", val_or_offset)
            if offset + count <= len(tiff_bytes):
                raw = tiff_bytes[offset:offset + count]
            else:
                raw = b""
        # Check if ASCII UserComment or string
        try:
            if raw.startswith(b"ASCII\x00\x00\x00"):
                return tag, raw[8:].decode("utf-8", errors="replace").strip("\x00").strip()
            elif raw.isascii() and len(raw) > 0:
                return tag, raw.decode("ascii", errors="replace").strip("\x00").strip()
        except Exception:
            pass
        return tag, f"<binary data: {len(raw)} bytes>"

    return tag, None


def _parse_tiff_ifd(tiff_bytes: bytes, ifd_offset: int, endian: str, tag_dict: Dict[int, str]) -> Dict[str, Any]:
    """Parse all entries in a TIFF IFD."""
    results = {}
    if ifd_offset + 2 > len(tiff_bytes):
        return results

    try:
        num_entries, = struct.unpack(endian + "H", tiff_bytes[ifd_offset:ifd_offset + 2])
    except struct.error:
        return results

    curr = ifd_offset + 2
    for _ in range(num_entries):
        if curr + 12 > len(tiff_bytes):
            break
        entry_bytes = tiff_bytes[curr:curr + 12]
        curr += 12
        tag, val = _parse_tiff_entry(endian, entry_bytes, tiff_bytes)
        if tag is not None and val is not None:
            tag_name = tag_dict.get(tag, f"Unknown Tag (0x{tag:04X})")
            results[tag_name] = val
    return results


def parse_exif_tiff(tiff_bytes: bytes) -> Dict[str, Any]:
    """
    Parse a complete TIFF structure (used by both JPEG APP1 Exif and PNG eXIf chunk).
    Extracts IFD0, Exif SubIFD, and GPS SubIFD.
    """
    metadata: Dict[str, Any] = {}
    if len(tiff_bytes) < 8:
        return metadata

    header = tiff_bytes[:2]
    if header == b"II":
        endian = "<"
    elif header == b"MM":
        endian = ">"
    else:
        return metadata

    magic, ifd0_offset = struct.unpack(endian + "HI", tiff_bytes[2:8])
    if magic != 42 or ifd0_offset >= len(tiff_bytes):
        return metadata

    # 1. Parse IFD0
    ifd0 = _parse_tiff_ifd(tiff_bytes, ifd0_offset, endian, TIFF_TAGS)
    exif_offset = ifd0.pop("Exif Offset", None)
    gps_offset = ifd0.pop("GPS Info Offset", None)

    for k, v in ifd0.items():
        if not k.startswith("Unknown Tag"):
            metadata[k] = v

    # 2. Parse Exif SubIFD
    if isinstance(exif_offset, int) and 0 < exif_offset < len(tiff_bytes):
        exif_sub = _parse_tiff_ifd(tiff_bytes, exif_offset, endian, EXIF_SUBIFD_TAGS)
        for k, v in exif_sub.items():
            if not k.startswith("Unknown Tag"):
                metadata[k] = v

    # 3. Parse GPS SubIFD
    if isinstance(gps_offset, int) and 0 < gps_offset < len(tiff_bytes):
        gps_raw = _parse_tiff_ifd(tiff_bytes, gps_offset, endian, GPS_TAGS)
        # Format GPS Coordinates
        lat = gps_raw.get("GPS Latitude")
        lat_ref = gps_raw.get("GPS Latitude Ref", "N")
        lon = gps_raw.get("GPS Longitude")
        lon_ref = gps_raw.get("GPS Longitude Ref", "W")

        if isinstance(lat, (list, tuple)) and len(lat) >= 3 and isinstance(lon, (list, tuple)) and len(lon) >= 3:
            try:
                lat_deg, lat_min, lat_sec = float(lat[0]), float(lat[1]), float(lat[2])
                lon_deg, lon_min, lon_sec = float(lon[0]), float(lon[1]), float(lon[2])

                dec_lat = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
                if lat_ref in ("S", "s"):
                    dec_lat = -dec_lat

                dec_lon = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)
                if lon_ref in ("W", "w"):
                    dec_lon = -dec_lon

                dms_str = f"{int(lat_deg)}°{int(lat_min)}'{lat_sec:.2f}\"{lat_ref}, {int(lon_deg)}°{int(lon_min)}'{lon_sec:.2f}\"{lon_ref}"
                metadata["GPS Latitude"] = f"{lat_deg:.0f}° {lat_min:.0f}' {lat_sec:.2f}\" {lat_ref} ({dec_lat:.6f}°)"
                metadata["GPS Longitude"] = f"{lon_deg:.0f}° {lon_min:.0f}' {lon_sec:.2f}\" {lon_ref} ({dec_lon:.6f}°)"
                metadata["GPS Coordinates"] = f"{dms_str} ({dec_lat:.6f}, {dec_lon:.6f})"
            except Exception:
                metadata["GPS Latitude Raw"] = f"{lat} {lat_ref}"
                metadata["GPS Longitude Raw"] = f"{lon} {lon_ref}"

        # Altitude
        alt = gps_raw.get("GPS Altitude")
        alt_ref = gps_raw.get("GPS Altitude Ref", 0)
        if isinstance(alt, (int, float)):
            ref_str = "below sea level" if alt_ref == 1 else "above sea level"
            metadata["GPS Altitude"] = f"{alt:.1f} m ({ref_str})"

        # Timestamp & Date
        gps_time = gps_raw.get("GPS Time Stamp")
        gps_date = gps_raw.get("GPS Date Stamp")
        if isinstance(gps_time, (list, tuple)) and len(gps_time) >= 3:
            try:
                h, m, s = int(gps_time[0]), int(gps_time[1]), float(gps_time[2])
                time_str = f"{h:02d}:{m:02d}:{s:05.2f} UTC"
                metadata["GPS Timestamp"] = f"{gps_date} {time_str}" if gps_date else time_str
            except Exception:
                pass
        elif gps_date:
            metadata["GPS Datestamp"] = gps_date

        if "GPS Map Datum" in gps_raw:
            metadata["GPS Map Datum"] = gps_raw["GPS Map Datum"]

    return metadata


# ============================================================
# JPEG / JPG EXTRACTOR
# ============================================================

def extract_jpeg_metadata(data: bytes) -> Dict[str, Any]:
    """
    Extract metadata from a JPEG byte stream.
    Scans for APP1 (Exif & XMP), APP13 (Photoshop/IPTC), and COM markers.
    """
    metadata: Dict[str, Any] = {}
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return metadata

    idx = 2
    while idx < len(data) - 4:
        if data[idx] != 0xFF:
            idx += 1
            continue

        marker = data[idx + 1]
        idx += 2

        # Standalone markers without payload
        if marker in (0xD8, 0xD9, 0x00) or (0xD0 <= marker <= 0xD7):
            continue

        # Start of Scan (SOS): raw image data begins, marker headers end
        if marker == 0xDA:
            break

        if idx + 2 > len(data):
            break

        seg_len, = struct.unpack(">H", data[idx:idx + 2])
        if seg_len < 2:
            break

        seg_data = data[idx + 2:idx + seg_len]
        idx += seg_len

        # APP1 Marker: Exif or XMP
        if marker == 0xE1:
            if seg_data.startswith(b"Exif\x00\x00"):
                tiff_bytes = seg_data[6:]
                exif_dict = parse_exif_tiff(tiff_bytes)
                metadata.update(exif_dict)
            elif seg_data.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                # Basic XMP text detection without full XML parser dependency
                metadata["Embedded XMP Packet"] = "Present (Adobe XMP Metadata Package)"

        # COM Marker: Comment
        elif marker == 0xFE:
            try:
                comment_text = seg_data.decode("utf-8", errors="replace").strip()
                if comment_text:
                    metadata["JPEG Comment"] = comment_text
            except Exception:
                pass

        # SOF0 / SOF2: Baseline / Progressive DCT (Dimensions)
        elif marker in (0xC0, 0xC2) and len(seg_data) >= 5:
            try:
                precision, height, width = struct.unpack(">BHH", seg_data[:5])
                metadata["Image Dimensions"] = f"{width} × {height} px"
            except Exception:
                pass

    return metadata


# ============================================================
# PNG EXTRACTOR
# ============================================================

def extract_png_metadata(data: bytes) -> Dict[str, Any]:
    """
    Extract metadata from a PNG byte stream.
    Scans for IHDR, tEXt, zTXt, iTXt, eXIf, and tIME chunks.
    """
    metadata: Dict[str, Any] = {}
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return metadata

    idx = 8
    while idx < len(data) - 8:
        try:
            chunk_len, chunk_type = struct.unpack(">I4s", data[idx:idx + 8])
        except struct.error:
            break

        idx += 8
        if idx + chunk_len > len(data):
            break

        chunk_data = data[idx:idx + chunk_len]
        idx += chunk_len + 4  # skip data + 4 bytes CRC

        # IHDR: Image Dimensions
        if chunk_type == b"IHDR" and len(chunk_data) >= 8:
            try:
                width, height = struct.unpack(">II", chunk_data[:8])
                metadata["Image Dimensions"] = f"{width} × {height} px"
            except Exception:
                pass

        # tEXt: Latin-1 Keyword + Null + Text
        elif chunk_type == b"tEXt":
            if b"\x00" in chunk_data:
                keyword, text = chunk_data.split(b"\x00", 1)
                k_str = keyword.decode("latin-1", errors="replace").strip()
                v_str = text.decode("latin-1", errors="replace").strip()
                if k_str and v_str:
                    metadata[f"PNG {k_str}"] = v_str

        # zTXt: Compressed Latin-1 text
        elif chunk_type == b"zTXt":
            if b"\x00" in chunk_data and len(chunk_data) > chunk_data.index(b"\x00") + 2:
                null_pos = chunk_data.index(b"\x00")
                k_str = chunk_data[:null_pos].decode("latin-1", errors="replace").strip()
                compressed_data = chunk_data[null_pos + 2:]
                try:
                    decompressed = zlib.decompress(compressed_data)
                    v_str = decompressed.decode("latin-1", errors="replace").strip()
                    if k_str and v_str:
                        metadata[f"PNG {k_str}"] = v_str
                except Exception:
                    pass

        # iTXt: UTF-8 international text
        elif chunk_type == b"iTXt":
            parts = chunk_data.split(b"\x00", 3)
            if len(parts) >= 4:
                k_str = parts[0].decode("utf-8", errors="replace").strip()
                flags = parts[1]
                comp_flag = flags[0] if len(flags) > 0 else 0
                raw_text = parts[3]
                if comp_flag == 1:
                    try:
                        raw_text = zlib.decompress(raw_text)
                    except Exception:
                        pass
                v_str = raw_text.decode("utf-8", errors="replace").strip()
                if k_str and v_str:
                    metadata[f"PNG {k_str}"] = v_str

        # eXIf: Standard Exif TIFF metadata chunk
        elif chunk_type == b"eXIf":
            exif_dict = parse_exif_tiff(chunk_data)
            metadata.update(exif_dict)

        # tIME: Last Modification Time
        elif chunk_type == b"tIME" and len(chunk_data) >= 7:
            try:
                year, month, day, hour, minute, second = struct.unpack(">HBBBBB", chunk_data[:7])
                metadata["PNG Timestamp (tIME)"] = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d} UTC"
            except Exception:
                pass

        elif chunk_type == b"IEND":
            break

    return metadata


# ============================================================
# SENSITIVE METADATA IDENTIFIER
# ============================================================

def identify_sensitive_metadata(metadata: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Examines extracted metadata and flags potentially sensitive privacy fields.
    Does NOT invent risk scores; cleanly explains why the field is sensitive.
    """
    sensitive_items = []
    seen_fields = set()

    for key, val in metadata.items():
        k_lower = key.lower()
        val_str = str(val).strip()
        if not val_str:
            continue

        # 1. GPS / Location
        if "gps" in k_lower or "latitude" in k_lower or "longitude" in k_lower or "coordinates" in k_lower:
            field_name = "GPS Coordinates" if "coordinates" in k_lower else key
            if field_name not in seen_fields:
                seen_fields.add(field_name)
                sensitive_items.append({
                    "category": "Location & GPS",
                    "field": field_name,
                    "value": val_str,
                    "description": "Reveals the exact geographic location where the file/photo was captured."
                })

        # 2. Camera / Device Hardware Information
        elif any(term in k_lower for term in ["camera make", "camera model", "serial number", "owner name", "lens model"]):
            if key not in seen_fields:
                seen_fields.add(key)
                sensitive_items.append({
                    "category": "Device & Hardware Identification",
                    "field": key,
                    "value": val_str,
                    "description": "Exposes specific device hardware, serial number, or equipment model."
                })

        # 3. Personal / Author Identification
        elif any(term in k_lower for term in ["artist", "author", "copyright", "owner", "user comment"]):
            if key not in seen_fields:
                seen_fields.add(key)
                sensitive_items.append({
                    "category": "Personal Identification",
                    "field": key,
                    "value": val_str,
                    "description": "Exposes creator or user identity, names, or commentary."
                })

        # 4. Software / Editing Environment
        elif "software" in k_lower or "tool" in k_lower or "xmp" in k_lower:
            if key not in seen_fields:
                seen_fields.add(key)
                sensitive_items.append({
                    "category": "Software & Environment",
                    "field": key,
                    "value": val_str,
                    "description": "Reveals software applications or editing workflows used on the file."
                })

        # 5. Precise Capture Timestamps
        elif any(term in k_lower for term in ["date & time original", "date & time digitized", "creation time"]):
            if key not in seen_fields:
                seen_fields.add(key)
                sensitive_items.append({
                    "category": "Creation Timestamp",
                    "field": key,
                    "value": val_str,
                    "description": "Exposes the exact date and time the media was originally captured."
                })

    return sensitive_items


# ============================================================
# MAIN SERVICE API
# ============================================================

def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Main synchronous analyzer for a user-selected file.
    Validates file safely, extracts available metadata, and identifies sensitive items.
    """
    if not file_path or not isinstance(file_path, str):
        return {
            "status": "ERROR",
            "message": "Invalid file path provided.",
            "results": {}
        }

    # 1. Existence and readability validation
    if not os.path.exists(file_path):
        return {
            "status": "ERROR",
            "message": f"File does not exist: {os.path.basename(file_path)}",
            "results": {}
        }

    if not os.path.isfile(file_path):
        return {
            "status": "ERROR",
            "message": "Path is a directory, not a regular file.",
            "results": {}
        }

    if not os.access(file_path, os.R_OK):
        return {
            "status": "ERROR",
            "message": "Permission denied: Unable to read file.",
            "results": {}
        }

    try:
        stat_res = os.stat(file_path)
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Could not read file attributes: {str(e)}",
            "results": {}
        }

    file_name = os.path.basename(file_path)
    size_bytes = stat_res.st_size
    size_formatted = format_file_size(size_bytes)

    created_dt = datetime.fromtimestamp(stat_res.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
    modified_dt = datetime.fromtimestamp(stat_res.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    accessed_dt = datetime.fromtimestamp(stat_res.st_atime).strftime("%Y-%m-%d %H:%M:%S")

    # Read header bytes safely (read-only, maximum 64KB for inspection or entire file if smaller than 50MB)
    try:
        # Check size to prevent memory exhaustion on giant files
        with open(file_path, "rb") as f:
            header_bytes = f.read(64)
            f.seek(0)
            # Read first 10MB maximum for embedded metadata extraction
            file_bytes = f.read(10 * 1024 * 1024)
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error reading file content: {str(e)}",
            "results": {}
        }

    file_type_desc, mime_type, is_supported = detect_file_type(file_path, header_bytes)

    file_info = {
        "file_name": file_name,
        "file_path": os.path.abspath(file_path),
        "file_size": size_formatted,
        "file_size_bytes": size_bytes,
        "file_type": file_type_desc,
        "mime_type": mime_type,
        "created_time": created_dt,
        "modified_time": modified_dt,
        "accessed_time": accessed_dt,
    }

    if not is_supported:
        return {
            "status": "SUCCESS",
            "message": f"File type '{file_type_desc}' is unsupported for deep embedded metadata extraction in v1. Standard file details collected.",
            "results": {
                "file_info": file_info,
                "is_supported": False,
                "metadata_found": False,
                "metadata": {},
                "potentially_sensitive": []
            }
        }

    # Extract metadata according to format
    extracted_metadata: Dict[str, Any] = {}
    try:
        if mime_type == "image/jpeg":
            extracted_metadata = extract_jpeg_metadata(file_bytes)
        elif mime_type == "image/png":
            extracted_metadata = extract_png_metadata(file_bytes)
    except Exception as e:
        return {
            "status": "SUCCESS",
            "message": f"Metadata extraction failed gracefully: {str(e)}",
            "results": {
                "file_info": file_info,
                "is_supported": True,
                "metadata_found": False,
                "metadata": {},
                "potentially_sensitive": []
            }
        }

    metadata_found = bool(extracted_metadata)
    sensitive_items = identify_sensitive_metadata(extracted_metadata) if metadata_found else []

    if metadata_found:
        msg = f"Analysis complete. Extracted {len(extracted_metadata)} metadata fields ({len(sensitive_items)} potentially sensitive)."
    else:
        msg = f"Analysis complete. No embedded metadata found in {file_name}."

    return {
        "status": "SUCCESS",
        "message": msg,
        "results": {
            "file_info": file_info,
            "is_supported": True,
            "metadata_found": metadata_found,
            "metadata": extracted_metadata,
            "potentially_sensitive": sensitive_items
        }
    }


async def check_file_metadata(file_path: str) -> Dict[str, Any]:
    """Async entrypoint for scan controller and worker compatibility."""
    return analyze_file(file_path)

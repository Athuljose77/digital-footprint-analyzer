"""Report export entry point.

One function writes any format to a user-chosen destination and reports
failures as a clear message rather than a traceback: the caller decides how to
tell the user. Nothing is written until the report has been fully rendered, so
a failure cannot leave a half-written file behind.
"""

import os
from pathlib import Path
from typing import Union

from app.core.reporting.errors import ReportExportError
from app.core.reporting.csv_export import encode_csv, render_csv
from app.core.reporting.json_export import render_json
from app.core.reporting.models import ReportBundle
from app.core.reporting.pdf_export import render_pdf

FORMAT_JSON = "json"
FORMAT_CSV = "csv"
FORMAT_PDF = "pdf"
FORMATS = (FORMAT_JSON, FORMAT_CSV, FORMAT_PDF)

EXTENSIONS = {
    FORMAT_JSON: ".json",
    FORMAT_CSV: ".csv",
    FORMAT_PDF: ".pdf",
}

FORMAT_LABELS = {
    FORMAT_PDF: "PDF report",
    FORMAT_JSON: "JSON data",
    FORMAT_CSV: "CSV spreadsheet",
}


def normalize_path(path: Union[str, os.PathLike], fmt: str) -> Path:
    """Validate the destination and give the file the right extension."""
    if fmt not in FORMATS:
        raise ReportExportError(f"Unsupported report format: {fmt!r}")

    raw = str(path or "").strip()
    if not raw:
        raise ReportExportError("No destination was chosen for the report.")

    destination = Path(raw).expanduser()
    if destination.is_dir():
        raise ReportExportError(
            f"'{destination}' is a folder. Choose a file name for the report.")

    if destination.suffix.lower() != EXTENSIONS[fmt]:
        destination = destination.with_suffix(EXTENSIONS[fmt])

    if not destination.parent.exists():
        raise ReportExportError(
            f"The folder '{destination.parent}' does not exist.")

    if not os.access(destination.parent, os.W_OK):
        raise ReportExportError(
            f"There is no permission to write to '{destination.parent}'.")

    return destination


def render(bundle: ReportBundle, fmt: str) -> bytes:
    """Render a bundle to bytes without touching the filesystem."""
    if fmt == FORMAT_JSON:
        return render_json(bundle).encode("utf-8")
    if fmt == FORMAT_CSV:
        return encode_csv(render_csv(bundle))
    if fmt == FORMAT_PDF:
        # Qt renders PDFs straight to a device, so render into a scratch
        # directory and hand back the bytes.
        import tempfile

        with tempfile.TemporaryDirectory(prefix="dfa-report-") as scratch:
            target = Path(scratch) / "report.pdf"
            render_pdf(bundle, target)
            return target.read_bytes()
    raise ReportExportError(f"Unsupported report format: {fmt!r}")


def export_report(bundle: ReportBundle, path: Union[str, os.PathLike],
                  fmt: str) -> Path:
    """Write *bundle* to *path* in *fmt* and return the path written."""
    destination = normalize_path(path, fmt)

    try:
        if fmt == FORMAT_PDF:
            render_pdf(bundle, destination)
        else:
            payload = render(bundle, fmt)
            with open(destination, "wb") as handle:
                handle.write(payload)
    except ReportExportError:
        raise
    except OSError as exc:
        raise ReportExportError(
            f"Could not write the report to '{destination}': {exc.strerror or exc}"
        ) from exc
    except Exception as exc:  # pragma: no cover - unexpected renderer failure
        raise ReportExportError(f"Could not create the report: {exc}") from exc

    if not destination.exists() or destination.stat().st_size == 0:
        raise ReportExportError(
            f"The report file '{destination}' was created but is empty.")

    return destination

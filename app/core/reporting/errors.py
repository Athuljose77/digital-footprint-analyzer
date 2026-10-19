"""Error type shared by the report exporters."""


class ReportExportError(RuntimeError):
    """Raised when a report cannot be written to the chosen destination."""

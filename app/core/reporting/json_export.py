"""JSON report export.

The JSON form is the complete, machine-readable bundle: what the other two
formats show is a subset of this. It carries no dates beyond the scan's own
timestamps and no values that were not already sanitized.
"""

import json
from typing import Any, Dict

from app.core.reporting.models import ReportBundle

INDENT = 2


def bundle_to_dict(bundle: ReportBundle) -> Dict[str, Any]:
    """Plain dictionary form of a bundle."""
    data = bundle.model_dump()
    data["title"] = bundle.title
    return data


def render_json(bundle: ReportBundle, indent: int = INDENT) -> str:
    """Serialize a bundle to JSON text."""
    return json.dumps(bundle_to_dict(bundle), indent=indent,
                      ensure_ascii=False, sort_keys=False, default=str)

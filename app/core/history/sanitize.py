"""Sanitization for anything that is written to disk or into a report.

Scan history and exported reports are files that can be shared, mailed, or
backed up, so they must not carry credentials, tokens, full local paths, or
other people's email addresses. Everything written through the history store
or the report exporters passes through here first.

What is deliberately kept:

* GPS coordinates, because a location finding is meaningless without them.
* Domains and URLs, because they are the actionable part of a finding.
* Usernames as they were scanned, minus the email local part.

What is removed or reduced:

* Bearer tokens, API keys, passwords, and any long opaque token-like run.
* Full filesystem paths, which are reduced to the file name.
* Email local parts, which are reduced to the first character.
"""

import re
from pathlib import Path
from typing import Any, Iterable, List, Optional

MAX_EVIDENCE_ITEMS = 5
MAX_EVIDENCE_LEN = 200
MAX_DESCRIPTION_LEN = 280

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)

# Opaque credential-like runs: long unbroken alphanumeric/base64/hex strings.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _looks_like_token(text: str) -> bool:
    """True when a run of characters looks like a credential, not a word.

    Plain prose in a finding title can easily exceed the length threshold —
    "multi-factor-authentication" is one word — so a match also has to look
    like machine text: mixed letters and digits, a long hex run, or a long
    mixed-case base64-style run.
    """
    has_digit = any(c.isdigit() for c in text)
    has_alpha = any(c.isalpha() for c in text)
    if has_digit and has_alpha:
        return True
    if len(text) >= 32 and all(c in _HEX_CHARS for c in text):
        return True
    if (len(text) >= 24 and any(c.islower() for c in text)
            and any(c.isupper() for c in text)):
        return True
    return False

# Explicit "key: value" style secrets. The separator is mandatory so that
# ordinary text containing a word like "secret" is never mistaken for a
# credential assignment.
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(bearer|token|api[_-]?key|apikey|secret|password|passwd|pwd|"
    r"authorization|session[_-]?id|serial(?:[_-]?number)?)\b\s*[:=]\s*\S+")

_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")

_PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s\"']*|(?:/[^\s\"'/]+){2,}/?)")

_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")

REDACTED = "[redacted]"
_PATH_PLACEHOLDER = "\x00PATH\x00"
_URL_PLACEHOLDER = "\x00URL\x00"


def mask_email(value: str) -> str:
    """Reduce an address to ``a***@domain`` so it stays recognisable, not reusable."""

    def _sub(match: "re.Match[str]") -> str:
        local, domain = match.group(1), match.group(2)
        head = local[0] if local else "*"
        return f"{head}***@{domain}"

    return _EMAIL_RE.sub(_sub, value)


def basename_only(value: str) -> str:
    """Return just the file name for a filesystem path."""
    try:
        name = Path(value).name
    except (ValueError, OSError):
        return value
    return name or value


def sanitize_text(value: Any, limit: int = MAX_EVIDENCE_LEN) -> str:
    """Return a shareable, length-capped version of one text value."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""

    # Protect URLs first: their path segments are meaningful, not local paths.
    urls: List[str] = []

    def _stash(match: "re.Match[str]") -> str:
        urls.append(match.group(0))
        return f"{_URL_PLACEHOLDER}{len(urls) - 1}{_URL_PLACEHOLDER}"

    text = _URL_RE.sub(_stash, text)

    text = _PATH_RE.sub(lambda m: basename_only(m.group(0) or ""), text)
    text = _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    text = _BEARER_RE.sub(lambda m: f"bearer={REDACTED}", text)
    text = _TOKEN_RE.sub(
        lambda m: REDACTED if _looks_like_token(m.group(0)) else m.group(0), text)
    text = _EMAIL_RE.sub(lambda m: f"{m.group(1)[0:1]}***@{m.group(2)}", text)

    for index, url in enumerate(urls):
        text = text.replace(f"{_URL_PLACEHOLDER}{index}{_URL_PLACEHOLDER}", url)

    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: max(limit - 1, 0)].rstrip() + "…"
    return text


def sanitize_target(value: Optional[str]) -> str:
    """Label for what a scan targeted, with the sensitive part reduced."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if "@" in text:
        return mask_email(text)[:120]
    if "/" in text or "\\" in text:
        return basename_only(text)[:120]
    return sanitize_text(text, limit=120)


def sanitize_evidence(evidence: Any,
                      limit: int = MAX_EVIDENCE_ITEMS) -> List[str]:
    """Flatten evidence into a capped list of shareable strings."""
    items: List[str] = []

    def _walk(node: Any) -> None:
        if len(items) >= limit:
            return
        if node is None:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                if len(items) >= limit:
                    return
                if isinstance(val, (dict, list, tuple, set)):
                    _walk(val)
                else:
                    text = sanitize_text(f"{key}: {val}")
                    if text:
                        items.append(text)
            return
        if isinstance(node, (list, tuple, set)):
            for entry in node:
                if len(items) >= limit:
                    return
                _walk(entry)
            return
        text = sanitize_text(node)
        if text:
            items.append(text)

    _walk(evidence)
    return items[:limit]


def content_signature(severity: str, status: str, verification: Optional[str],
                      evidence_preview: Iterable[str]) -> str:
    """Stable fingerprint of a finding's *content* (not its identity).

    Used by scan comparison to tell "unchanged" from "modified" without
    relying on scan-specific ids.
    """
    import hashlib

    parts = [
        str(severity or "").strip().lower(),
        str(status or "").strip().lower(),
        str(verification or "").strip().lower(),
        "|".join(str(e) for e in evidence_preview),
    ]
    return hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:16]

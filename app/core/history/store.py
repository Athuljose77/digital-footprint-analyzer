"""Durable local scan history.

Storage is a single SQLite database (Python's stdlib ``sqlite3``, no extra
dependency) holding one row per completed scan. Nothing leaves the machine:
the file lives under the platform data directory, the user can delete any
record or clear the whole history from the UI, and deleting the file has the
same effect.

The path is injectable so tests never touch real user data, and the default
honours ``XDG_DATA_HOME``.
"""

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from app.core.findings.models import make_identity_key
from app.core.history.models import ScanRecord, StoredFinding
from app.core.history.sanitize import (
    MAX_DESCRIPTION_LEN,
    content_signature,
    sanitize_evidence,
    sanitize_target,
    sanitize_text,
)

SCHEMA_VERSION = 1


class HistoryStoreError(RuntimeError):
    """Raised when history cannot be read or written."""


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


APP_DIR_NAME = "DigitalFootprintAnalyzer"


def default_data_dir() -> Path:
    """Directory the application keeps local data in.

    On Linux this is the XDG data directory (``$XDG_DATA_HOME`` or
    ``~/.local/share``) plus the application folder, which is where a desktop
    application is expected to keep its own data. ``DFA_DATA_DIR`` overrides
    it entirely, and tests always inject a path.
    """
    override = os.environ.get("DFA_DATA_DIR")
    if override:
        return Path(override).expanduser()

    if os.name == "nt":  # pragma: no cover - not exercised on Linux CI
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base).expanduser() if base else Path.home() / "AppData" / "Local"
        return root / APP_DIR_NAME

    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / APP_DIR_NAME


def default_db_path() -> Path:
    """Location of the history database."""
    override = os.environ.get("DFA_HISTORY_DB")
    if override:
        return Path(override).expanduser()
    return default_data_dir() / "history.db"


def stored_finding(finding) -> StoredFinding:
    """Convert an in-memory Finding into its persisted, sanitized form."""
    evidence_preview = sanitize_evidence(getattr(finding, "evidence", None))
    severity = str(getattr(finding, "severity", "") or "Info")
    status = str(getattr(finding, "status", "") or "Informational")
    verification = getattr(finding, "verification", None)
    key = getattr(finding, "identity_key", None) or make_identity_key(
        getattr(finding, "rule_id", None),
        getattr(finding, "finding_type", None),
        getattr(finding, "title", None),
    )
    return StoredFinding(
        identity_key=str(key),
        title=sanitize_text(getattr(finding, "title", ""), limit=160),
        description=sanitize_text(getattr(finding, "description", ""),
                                  limit=MAX_DESCRIPTION_LEN),
        finding_type=str(getattr(finding, "finding_type", "") or "General"),
        category=str(getattr(finding, "category", "") or "Observation"),
        severity=severity,
        status=status,
        source_module=getattr(finding, "source_module", None),
        sources=[str(s) for s in (getattr(finding, "sources", None) or []) if s],
        verification=verification,
        confidence=getattr(finding, "confidence", None),
        evidence_preview=evidence_preview,
        signature=content_signature(severity, status, verification, evidence_preview),
    )


def record_from_result(
    result,
    risk_summary=None,
    target: Optional[str] = None,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> ScanRecord:
    """Build the record that will be persisted for one finished scan."""
    risk = risk_summary.model_dump() if risk_summary is not None else {}
    findings = [stored_finding(f) for f in (getattr(result, "findings", None) or [])]

    return ScanRecord(
        scan_id=str(getattr(result, "scan_id", "") or ""),
        scan_type=str(getattr(result, "scan_type", "") or ""),
        status=str(getattr(result, "status", "") or ""),
        started_at=started_at or getattr(result, "started_at", "") or "",
        finished_at=finished_at or getattr(result, "finished_at", "") or utc_now_iso(),
        created_at=utc_now_iso(),
        score=risk.get("score"),
        band=risk.get("band", ""),
        methodology_version=risk.get("methodology_version", ""),
        coverage_key=risk.get("coverage_key", ""),
        confidence=risk.get("confidence", ""),
        target_label=sanitize_target(target),
        counts=dict(risk.get("counts", {}) or {}),
        modules=[dict(m) for m in (risk.get("modules", []) or [])],
        findings=findings,
        risk=risk,
    )


class ScanHistoryStore:
    """SQLite-backed scan history. Reads and writes are short-lived."""

    def __init__(self, db_path: Optional[os.PathLike | str] = None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self._ensure_schema()

    # -- schema ---------------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(self.db_path), timeout=5.0)
        except (sqlite3.Error, OSError) as exc:
            raise HistoryStoreError(f"Cannot open scan history: {exc}") from exc
        try:
            connection.row_factory = sqlite3.Row
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise HistoryStoreError(f"Scan history operation failed: {exc}") from exc
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL DEFAULT '',
                    finished_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT '',
                    score INTEGER,
                    band TEXT NOT NULL DEFAULT '',
                    methodology_version TEXT NOT NULL DEFAULT '',
                    coverage_key TEXT NOT NULL DEFAULT '',
                    confidence TEXT NOT NULL DEFAULT '',
                    target_label TEXT NOT NULL DEFAULT '',
                    counts_json TEXT NOT NULL DEFAULT '{}',
                    modules_json TEXT NOT NULL DEFAULT '[]',
                    findings_json TEXT NOT NULL DEFAULT '[]',
                    risk_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_finished "
                "ON scans(finished_at DESC, id DESC)"
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # -- writes ---------------------------------------------------------

    def record_scan(
        self,
        result,
        risk_summary=None,
        target: Optional[str] = None,
        started_at: Optional[str] = None,
        finished_at: Optional[str] = None,
    ) -> ScanRecord:
        """Persist one finished scan and return the stored record."""
        record = record_from_result(
            result, risk_summary=risk_summary, target=target,
            started_at=started_at, finished_at=finished_at,
        )

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    scan_id, scan_type, status, started_at, finished_at,
                    created_at, score, band, methodology_version, coverage_key,
                    confidence, target_label, counts_json, modules_json,
                    findings_json, risk_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.scan_id or str(uuid.uuid4()),
                    record.scan_type,
                    record.status,
                    record.started_at,
                    record.finished_at,
                    record.created_at,
                    record.score,
                    record.band,
                    record.methodology_version,
                    record.coverage_key,
                    record.confidence,
                    record.target_label,
                    json.dumps(record.counts, default=str),
                    json.dumps(record.modules, default=str),
                    json.dumps([f.model_dump() for f in record.findings], default=str),
                    json.dumps(record.risk, default=str),
                ),
            )
            record.id = int(cursor.lastrowid or 0)
        return record

    def delete_scan(self, record_id: int) -> bool:
        """Delete one record. Returns True when a row was removed."""
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM scans WHERE id = ?", (int(record_id),))
            return cursor.rowcount > 0

    def clear(self) -> int:
        """Delete every record. Returns how many were removed."""
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM scans")
            return int(cursor.rowcount or 0)

    # -- reads ----------------------------------------------------------

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
        return int(row["n"] if row else 0)

    def list_scans(self, limit: Optional[int] = None) -> List[ScanRecord]:
        """Most recent scans first."""
        query = "SELECT * FROM scans ORDER BY finished_at DESC, id DESC"
        params: tuple = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (int(limit),)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_scan(self, record_id: int) -> Optional[ScanRecord]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (int(record_id),)).fetchone()
        return self._row_to_record(row) if row else None

    def latest_scan(self) -> Optional[ScanRecord]:
        records = self.list_scans(limit=1)
        return records[0] if records else None

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _loads(raw: Any, fallback: Any) -> Any:
        if not raw:
            return fallback
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return fallback

    def _row_to_record(self, row: sqlite3.Row) -> ScanRecord:
        findings_raw = self._loads(row["findings_json"], [])
        findings: List[StoredFinding] = []
        for entry in findings_raw if isinstance(findings_raw, list) else []:
            if not isinstance(entry, dict):
                continue
            try:
                findings.append(StoredFinding(**entry))
            except Exception:
                # A record written by an older/newer schema must never break
                # the whole history view; skip the unreadable row.
                continue

        counts = self._loads(row["counts_json"], {})
        modules = self._loads(row["modules_json"], [])
        risk = self._loads(row["risk_json"], {})

        return ScanRecord(
            id=int(row["id"]),
            scan_id=row["scan_id"],
            scan_type=row["scan_type"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            created_at=row["created_at"],
            score=row["score"],
            band=row["band"],
            methodology_version=row["methodology_version"],
            coverage_key=row["coverage_key"],
            confidence=row["confidence"],
            target_label=row["target_label"],
            counts=counts if isinstance(counts, dict) else {},
            modules=modules if isinstance(modules, list) else [],
            findings=findings,
            risk=risk if isinstance(risk, dict) else {},
        )


_DEFAULT_STORE: Optional[ScanHistoryStore] = None


def default_store() -> ScanHistoryStore:
    """Process-wide store at the default location."""
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = ScanHistoryStore()
    return _DEFAULT_STORE


def reset_default_store(path: Optional[os.PathLike | str] = None) -> ScanHistoryStore:
    """Point the process-wide store at *path* (or the default). For tests."""
    global _DEFAULT_STORE
    _DEFAULT_STORE = ScanHistoryStore(path)
    return _DEFAULT_STORE

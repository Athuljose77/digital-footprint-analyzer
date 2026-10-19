"""Scan history storage tests.

Covers durability across "restarts", user-controlled deletion, and the
privacy guarantees: nothing sensitive may be written to the database, and a
broken row must never take the whole history view down with it.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core.history import (
    ScanHistoryStore,
    compare_scans,
    record_from_result,
)
from app.core.history.store import default_db_path
from app.core.risk import build_risk_summary
from app.models.common import Finding, FootprintData, ScanResult


def _scan(scan_type="Full Scan", status="COMPLETED", findings=(), footprint=(),
          message="ok"):
    return ScanResult(
        scan_id=f"{scan_type}-{status}",
        analysis_mode="Full Footprint Analysis",
        scan_type=scan_type,
        scan_category="Unified Footprint",
        status=status,
        message=message,
        footprint_data=list(footprint),
        findings=list(findings),
    )


def _finding(title="Embedded GPS Location Data Detected", severity="Medium",
             finding_type="Sensitive Metadata", rule_id="FILE-GPS-001",
             module="file_metadata", evidence=("35.6895, 139.6917",)):
    return Finding(
        finding_id="f1",
        finding_type=finding_type,
        title=title,
        description="Coordinates are embedded in this file.",
        evidence=list(evidence),
        severity=severity,
        status="Unremediated",
        rule_id=rule_id,
        source_module=module,
        verification="direct-observation",
        confidence="high",
    )


class HistoryStoreTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-history-test-")
        self.db_path = os.path.join(self.tmp, "history.db")
        self.store = ScanHistoryStore(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestHistoryRoundTrip(HistoryStoreTestBase):
    def test_empty_history_is_empty_not_an_error(self):
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.list_scans(), [])
        self.assertIsNone(self.store.latest_scan())
        self.assertIsNone(self.store.get_scan(999))

    def test_record_and_read_back(self):
        result = _scan(findings=[_finding()],
                       footprint=[FootprintData(
                           category="System", subcategory="Operating System",
                           source="t", data_type="String", value="Linux",
                           sensitivity="Low")])
        risk = build_risk_summary(result)
        stored = self.store.record_scan(result, risk_summary=risk,
                                        target="me@example.com")

        self.assertGreater(stored.id, 0)
        self.assertEqual(self.store.count(), 1)

        loaded = self.store.latest_scan()
        self.assertEqual(loaded.id, stored.id)
        self.assertEqual(loaded.scan_type, "Full Scan")
        self.assertEqual(loaded.score, risk.score)
        self.assertEqual(loaded.band, risk.band)
        self.assertEqual(loaded.methodology_version, risk.methodology_version)
        self.assertEqual(loaded.coverage_key, risk.coverage_key)
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0].severity, "Medium")
        self.assertEqual(loaded.findings[0].source_module, "file_metadata")

    def test_history_survives_a_restart(self):
        self.store.record_scan(_scan(), risk_summary=None)
        reopened = ScanHistoryStore(self.db_path)
        self.assertEqual(reopened.count(), 1)
        self.assertEqual(len(reopened.list_scans()), 1)

    def test_records_are_newest_first(self):
        for index in range(3):
            record = self.store.record_scan(_scan(), risk_summary=None)
            with self.store._connect() as connection:
                connection.execute(
                    "UPDATE scans SET finished_at = ? WHERE id = ?",
                    (f"2026-01-0{index + 1}T00:00:00Z", record.id))
        ordered = self.store.list_scans()
        self.assertEqual([r.finished_at for r in ordered],
                         ["2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z",
                          "2026-01-01T00:00:00Z"])

    def test_limit_is_applied(self):
        for _ in range(3):
            self.store.record_scan(_scan(), risk_summary=None)
        self.assertEqual(len(self.store.list_scans(limit=2)), 2)

    def test_scan_without_risk_summary_records_no_score(self):
        loaded_id = self.store.record_scan(_scan(status="ERROR"), risk_summary=None).id
        loaded = self.store.get_scan(loaded_id)
        self.assertIsNone(loaded.score)
        self.assertEqual(loaded.band, "")
        self.assertEqual(loaded.risk, {})


class TestHistoryDeletion(HistoryStoreTestBase):
    def test_delete_single_record_leaves_others(self):
        first = self.store.record_scan(_scan(), risk_summary=None)
        second = self.store.record_scan(_scan(), risk_summary=None)

        self.assertTrue(self.store.delete_scan(first.id))
        self.assertEqual(self.store.count(), 1)
        self.assertIsNone(self.store.get_scan(first.id))
        self.assertIsNotNone(self.store.get_scan(second.id))

    def test_deleting_a_missing_record_reports_false(self):
        self.assertFalse(self.store.delete_scan(12345))

    def test_clear_all_removes_everything(self):
        for _ in range(4):
            self.store.record_scan(_scan(), risk_summary=None)

        self.assertEqual(self.store.clear(), 4)
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.list_scans(), [])

    def test_deleting_the_file_is_equivalent_to_clearing(self):
        self.store.record_scan(_scan(), risk_summary=None)
        os.remove(self.db_path)
        fresh = ScanHistoryStore(self.db_path)
        self.assertEqual(fresh.count(), 0)


class TestHistoryPrivacy(HistoryStoreTestBase):
    def test_file_paths_are_reduced_to_the_file_name(self):
        secret_path = "/home/someone/private/projects/secret-plan.txt"
        finding = _finding(title="Device Metadata", finding_type="Device Metadata",
                           rule_id="FILE-CAMERA-001",
                           evidence=(secret_path, "metadata: full path " + secret_path))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None)
        loaded = self.store.list_scans()[0]
        blob = " ".join(loaded.findings[0].evidence_preview)
        self.assertNotIn("/home/someone/private", blob)
        self.assertIn("secret-plan.txt", blob)

    def test_tokens_are_redacted(self):
        token = "demo1234token5678value9012"
        finding = _finding(title="Startup Application", finding_type="Startup Application",
                           rule_id="SYS-STARTUP-001", module="system",
                           evidence=(f"command: run --token {token}",))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None)
        loaded = self.store.list_scans()[0]
        blob = " ".join(loaded.findings[0].evidence_preview)
        self.assertNotIn(token, blob)
        self.assertIn("redacted", blob.lower())

    def test_evidence_is_capped(self):
        finding = _finding(evidence=tuple(f"item {i}" for i in range(40)))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None)
        loaded = self.store.list_scans()[0]
        self.assertLessEqual(len(loaded.findings[0].evidence_preview), 5)

    def test_long_evidence_is_truncated(self):
        finding = _finding(evidence=("x" * 5000,))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None)
        loaded = self.store.list_scans()[0]
        self.assertLessEqual(len(loaded.findings[0].evidence_preview[0]), 200)

    def test_email_target_is_masked(self):
        self.store.record_scan(_scan(scan_type="Email"), risk_summary=None,
                               target="someone@example.com")
        loaded = self.store.list_scans()[0]
        self.assertEqual(loaded.target_label, "s***@example.com")

    def test_gps_coordinates_are_preserved(self):
        """A location finding is useless without the location."""
        finding = _finding(evidence=("35.6895, 139.6917",))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None)
        loaded = self.store.list_scans()[0]
        self.assertIn("35.6895, 139.6917", loaded.findings[0].evidence_preview)

    def test_raw_secret_never_reaches_the_database_file(self):
        token = "AKIAIOSFODNN7EXAMPLE1234"
        finding = _finding(title="System Configuration",
                           finding_type="System Configuration",
                           rule_id="SYS-STARTUP-001", module="system",
                           evidence=(f"api_key={token}",))
        self.store.record_scan(_scan(findings=[finding]), risk_summary=None,
                               target="user@example.com")

        with open(self.db_path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(token.encode(), raw)
        self.assertNotIn(b"AKIA", raw)


class TestHistoryResilience(HistoryStoreTestBase):
    def test_unreadable_finding_row_is_skipped_not_fatal(self):
        self.store.record_scan(_scan(findings=[_finding()]), risk_summary=None)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO scans (scan_id, scan_type, status, finished_at, "
                "findings_json) VALUES (?, ?, ?, ?, ?)",
                ("broken", "Full Scan", "COMPLETED", "2026-02-02T00:00:00Z",
                 '[{"identity_key": "k"}, "not-a-dict", {"bad": true}]'),
            )

        records = self.store.list_scans()
        self.assertEqual(len(records), 2)
        broken = [r for r in records if r.scan_id == "broken"][0]
        self.assertEqual(broken.findings, [])

    def test_invalid_json_columns_fall_back_to_defaults(self):
        with self.store._connect() as connection:
            connection.execute(
                "INSERT INTO scans (scan_id, scan_type, status, finished_at, "
                "counts_json, modules_json, risk_json) VALUES (?,?,?,?,?,?,?)",
                ("json-broken", "Full Scan", "COMPLETED", "2026-03-03T00:00:00Z",
                 "{not json", "[[[", "nope"),
            )
        record = [r for r in self.store.list_scans() if r.scan_id == "json-broken"][0]
        self.assertEqual(record.counts, {})
        self.assertEqual(record.modules, [])
        self.assertEqual(record.risk, {})

    def test_store_creates_missing_parent_directories(self):
        nested = os.path.join(self.tmp, "a", "b", "c", "history.db")
        store = ScanHistoryStore(nested)
        store.record_scan(_scan(), risk_summary=None)
        self.assertTrue(os.path.exists(nested))


class TestDefaultLocation(unittest.TestCase):
    def test_default_path_honours_explicit_override(self):
        previous = os.environ.get("DFA_HISTORY_DB")
        os.environ["DFA_HISTORY_DB"] = "/tmp/custom-history.db"
        try:
            self.assertEqual(str(default_db_path()), "/tmp/custom-history.db")
        finally:
            if previous is None:
                os.environ.pop("DFA_HISTORY_DB", None)
            else:
                os.environ["DFA_HISTORY_DB"] = previous

    def test_default_paths_track_the_data_directory(self):
        previous_db = os.environ.pop("DFA_HISTORY_DB", None)
        previous_data = os.environ.get("DFA_DATA_DIR")
        try:
            os.environ["DFA_DATA_DIR"] = "/tmp/dfa-data-dir"
            self.assertEqual(str(default_db_path()), "/tmp/dfa-data-dir/history.db")
            os.environ.pop("DFA_DATA_DIR", None)

            os.environ["XDG_DATA_HOME"] = "/tmp/dfa-xdg"
            self.assertEqual(
                str(default_db_path()),
                "/tmp/dfa-xdg/DigitalFootprintAnalyzer/history.db")
        finally:
            os.environ.pop("DFA_DATA_DIR", None)
            if previous_data is not None:
                os.environ["DFA_DATA_DIR"] = previous_data
            if previous_db is not None:
                os.environ["DFA_HISTORY_DB"] = previous_db


class TestRecordFromResult(unittest.TestCase):
    def test_record_carries_started_and_finished_times(self):
        result = _scan()
        result.started_at = "2026-04-01T10:00:00Z"
        result.finished_at = "2026-04-01T10:00:30Z"
        record = record_from_result(result)
        self.assertEqual(record.started_at, "2026-04-01T10:00:00Z")
        self.assertEqual(record.finished_at, "2026-04-01T10:00:30Z")

    def test_record_falls_back_to_now_when_times_are_missing(self):
        record = record_from_result(_scan())
        self.assertTrue(record.finished_at)
        self.assertTrue(record.created_at)

    def test_identity_key_is_derived_when_the_finding_has_none(self):
        finding = Finding(
            finding_id="random-uuid-1", finding_type="Email Breach",
            title="Exposed in Example", description="d", evidence=["e"],
            severity="High", status="Unremediated",
        )
        record = record_from_result(_scan(findings=[finding]))
        self.assertTrue(record.findings[0].identity_key)

        other = record_from_result(_scan(findings=[Finding(
            finding_id="random-uuid-2", finding_type="Email Breach",
            title="Exposed in Example", description="different", evidence=["other"],
            severity="High", status="Unremediated",
        )]))
        self.assertEqual(record.findings[0].identity_key,
                         other.findings[0].identity_key)

    def test_two_scans_can_be_compared_after_storage(self):
        store_path = os.path.join(tempfile.mkdtemp(prefix="dfa-cmp-"), "h.db")
        store = ScanHistoryStore(store_path)
        try:
            first = store.record_scan(_scan(findings=[_finding()]), risk_summary=None)
            second = store.record_scan(_scan(findings=[_finding()]), risk_summary=None)
            comparison = compare_scans(first, second)
            self.assertEqual(comparison.counts["unchanged"], 1)
        finally:
            shutil.rmtree(os.path.dirname(store_path), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

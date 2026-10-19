"""Remediation tests.

The contract under test: advice only ever comes from a fixed mapping to real
findings, never from a generic tips list; a scan with nothing to fix produces
an empty plan; and the user's own "done" mark is never presented as a
technical verification.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core.remediation import build_plan, plan_with_states
from app.core.remediation.catalogue import COVERAGE_TYPES, LINKS, TEMPLATES, template_for
from app.core.remediation.engine import pending_action_count
from app.core.remediation.models import COMPLETED, DISMISSED, PENDING
from app.core.remediation.store import ActionStateStore
from app.models.common import Finding, ScanResult
from app.core.findings_processor import with_provenance


def _finding(title="Exposed in Adobe", severity="High", finding_type="Email Breach",
             rule_id="EML-BREACH-001", evidence=("emails: 3",), module="email",
             verification="provider-verified"):
    return with_provenance(Finding(
        finding_id="f1",
        finding_type=finding_type,
        title=title,
        description="d",
        evidence=list(evidence),
        severity=severity,
        status="Unremediated",
        rule_id=rule_id,
    ), explicit_module=module, explicit_verification=verification)


def _result(findings=()):
    return ScanResult(
        scan_id="s1", analysis_mode="Full Footprint Analysis", scan_type="Full Scan",
        scan_category="Unified Footprint", status="COMPLETED", message="ok",
        findings=list(findings),
    )


class TestPlanFromFindings(unittest.TestCase):
    def test_scan_with_no_findings_produces_no_advice(self):
        plan = build_plan(_result())
        self.assertEqual(plan.actions, [])
        self.assertIn("nothing to do", plan.note)

    def test_empty_finding_list_produces_no_advice(self):
        plan = build_plan([])
        self.assertEqual(plan.actions, [])
        self.assertEqual(plan.unmapped_findings, 0)

    def test_breach_finding_produces_one_action_with_steps_and_docs(self):
        plan = build_plan(_result([_finding()]))
        self.assertEqual(len(plan.actions), 1)
        action = plan.actions[0]
        self.assertIn("Adobe", action.title)
        self.assertEqual(action.priority, "High")
        self.assertTrue(action.steps)
        self.assertTrue(action.docs)
        for link in action.docs:
            self.assertTrue(link.url.startswith("https://"))

    def test_coverage_findings_never_produce_actions(self):
        plan = build_plan(_result([
            _finding(title="Module Limitation: Browser", finding_type="Scan Limitation",
                     rule_id=None, severity="Info", module=None,
                     verification="not-applicable"),
            _finding(title="Scan coverage note", finding_type="Scan Coverage",
                     rule_id=None, severity="Info", module=None,
                     verification="not-applicable"),
        ]))
        self.assertEqual(plan.actions, [])
        self.assertEqual(plan.unmapped_findings, 0)

    def test_unknown_finding_type_is_counted_not_guessed(self):
        plan = build_plan([_finding(title="Something odd", finding_type="Mystery",
                                    rule_id=None, module="system")])
        self.assertEqual(plan.actions, [])
        self.assertEqual(plan.unmapped_findings, 1)
        self.assertEqual(plan.unmapped_types, ["Mystery"])
        self.assertIn("no mapped remediation action", plan.note)

    def test_action_key_is_stable_across_scans(self):
        first = build_plan(_result([_finding()])).actions[0]
        second = build_plan(_result([_finding(evidence=("emails: 4",))])).actions[0]
        self.assertEqual(first.action_key, second.action_key)

    def test_actions_are_prioritised_by_severity(self):
        plan = build_plan(_result([
            _finding(title="Exposed in LowCo", severity="Low"),
            _finding(title="Exposed in CriticalCo", severity="Critical"),
            _finding(title="Exposed in MediumCo", severity="Medium"),
        ]))
        self.assertEqual([a.priority for a in plan.actions],
                         ["Critical", "Medium", "Low"])

    def test_repeated_findings_for_one_subject_become_one_action(self):
        plan = build_plan([
            _finding(severity="Medium"),
            _finding(severity="High", evidence=("emails: 9",)),
        ])
        self.assertEqual(len(plan.actions), 1)
        self.assertEqual(plan.actions[0].severity, "High")

    def test_finding_provenance_is_carried_onto_the_action(self):
        plan = build_plan(_result([_finding()]))
        action = plan.actions[0]
        self.assertEqual(action.module, "email")
        self.assertIn("EML-BREACH-001", action.rule_ids)
        self.assertTrue(action.finding_titles)

    def test_unverified_evidence_is_flagged_to_check_first(self):
        plan = build_plan([_finding(verification="unconfirmed",
                                    finding_type="Public Presence",
                                    rule_id="USR-PROFILE-001",
                                    title="Public Profile Discovered on ExampleSite",
                                    module="username")])
        action = plan.actions[0]
        self.assertTrue(action.verify_first)
        self.assertIn("not verified", action.note.lower())

    def test_directly_observed_findings_are_not_flagged(self):
        plan = build_plan([_finding(title="Embedded GPS Location Data Detected",
                                    finding_type="Sensitive Metadata",
                                    rule_id="FILE-GPS-001", severity="Medium",
                                    module="file_metadata",
                                    verification="direct-observation")])
        self.assertFalse(plan.actions[0].verify_first)

    def test_file_paths_in_titles_are_reduced_to_the_file_name(self):
        plan = build_plan([_finding(
            title="Sensitive Metadata in /home/someone/private/holiday.jpg",
            finding_type="Sensitive Metadata", rule_id="FILE-GPS-001",
            severity="Medium", module="file_metadata",
            verification="direct-observation")])
        action = plan.actions[0]
        self.assertNotIn("/home/someone", action.title)
        self.assertIn("holiday.jpg", action.title)

    def test_every_shipped_doc_link_is_https(self):
        for key, link in LINKS.items():
            self.assertTrue(link.url.startswith("https://"), key)
            self.assertTrue(link.label, key)

    def test_every_template_has_steps_and_a_reason(self):
        for name, template in TEMPLATES.items():
            self.assertTrue(template.why, name)
            self.assertTrue(template.steps, name)

    def test_rule_and_type_mappings_resolve_to_real_templates(self):
        for finding in (
            _finding(),
            _finding(title="Public Profile Discovered on X",
                     finding_type="Public Presence", rule_id="USR-PROFILE-001"),
            _finding(title="System Configuration", finding_type="System Configuration",
                     rule_id=None),
            _finding(title="Sensitive Metadata", finding_type="Sensitive Metadata",
                     rule_id=None),
        ):
            name, template = template_for(finding)
            self.assertIsNotNone(name, finding.finding_type)
            self.assertIn(name, TEMPLATES)


class TestPlanWithStates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dfa-actions-test-")
        self.store = ActionStateStore(os.path.join(self.tmp, "actions.db"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_actions_start_pending(self):
        board = plan_with_states(build_plan(_result([_finding()])), self.store)
        self.assertEqual(board.pending, 1)
        self.assertEqual(board.items[0].state, PENDING)
        self.assertEqual(board.completed, 0)

    def test_completed_state_persists_across_restarts(self):
        plan = build_plan(_result([_finding()]))
        key = plan.actions[0].action_key
        self.store.set_state(key, COMPLETED)

        reopened = ActionStateStore(os.path.join(self.tmp, "actions.db"))
        board = plan_with_states(build_plan(_result([_finding()])), reopened)
        self.assertEqual(board.completed, 1)
        self.assertEqual(board.pending, 0)
        self.assertIn("Marked complete by you", board.items[0].status_note)

    def test_dismissed_state_is_kept_separate_from_pending(self):
        plan = build_plan(_result([_finding()]))
        self.store.set_state(plan.actions[0].action_key, DISMISSED)
        board = plan_with_states(build_plan(_result([_finding()])), self.store)
        self.assertEqual(board.dismissed, 1)
        self.assertEqual(board.pending, 0)

    def test_completed_but_still_detected_is_not_called_resolved(self):
        plan = build_plan(_result([_finding()]))
        self.store.set_state(plan.actions[0].action_key, COMPLETED)
        board = plan_with_states(build_plan(_result([_finding()])), self.store)
        self.assertNotIn("technically verified", board.items[0].status_note.lower())
        self.assertIn("Re-run the scan", board.items[0].status_note)

    def test_completed_and_no_longer_detected_is_reported_honestly(self):
        plan = build_plan(_result([_finding()]))
        key = plan.actions[0].action_key
        self.store.set_state(key, COMPLETED, title="Change the exposed password",
                             priority="High", module="email")

        board = plan_with_states(build_plan(_result()), self.store)
        self.assertEqual(board.completed_not_verified, 1)
        stale = board.not_detected[0]
        self.assertFalse(stale.present_in_latest_scan)
        self.assertIn("not a technical verification", stale.status_note)
        self.assertEqual(board.items, [])

    def test_pending_count_drives_the_dashboard(self):
        self.assertEqual(pending_action_count(_result([_finding()]), self.store), 1)
        self.assertEqual(pending_action_count(_result(), self.store), 0)

    def test_state_store_is_isolated_per_path(self):
        other = ActionStateStore(os.path.join(self.tmp, "other.db"))
        plan = build_plan(_result([_finding()]))
        self.store.set_state(plan.actions[0].action_key, COMPLETED)
        self.assertEqual(other.get_state(plan.actions[0].action_key), PENDING)

    def test_clear_state_returns_an_action_to_pending(self):
        plan = build_plan(_result([_finding()]))
        key = plan.actions[0].action_key
        self.store.set_state(key, COMPLETED)
        self.assertTrue(self.store.clear_state(key))
        self.assertEqual(self.store.get_state(key), PENDING)

    def test_unknown_state_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.set_state("some-key", "banana")

    def test_sync_does_not_reset_user_state(self):
        plan = build_plan(_result([_finding()]))
        key = plan.actions[0].action_key
        self.store.set_state(key, COMPLETED)
        self.store.sync(plan.actions)
        self.assertEqual(self.store.get_state(key), COMPLETED)

    def test_plan_still_renders_when_the_store_is_unavailable(self):
        class Broken:
            def sync(self, actions):
                raise RuntimeError("disk on fire")

            def all_states(self):
                raise RuntimeError("disk on fire")

        board = plan_with_states(build_plan(_result([_finding()])), Broken())
        self.assertEqual(board.pending, 1)

    def test_clear_removes_all_state(self):
        plan = build_plan(_result([_finding()]))
        self.store.set_state(plan.actions[0].action_key, COMPLETED)
        self.assertEqual(self.store.clear(), 1)
        self.assertEqual(self.store.count(), 0)


if __name__ == "__main__":
    unittest.main()

"""Windows process collector tests.

These run on any platform: the tasklist call is mocked, so the CSV parsing,
the evidence-cleaning rules, and the collector tiers are all verified without
a Windows host.

Regression focus: /V must stay in the command line. Dropping it removes the
User Name and Status columns and silently turns real evidence into
placeholders.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.services import system_service
from app.services.system_service import (
    DEFAULT_PROCESS_COLLECTOR_MODE,
    PROCESS_COLLECTOR_MODES,
    _clean_tasklist_field,
    collect_windows_processes,
)

CSV_WITH_VERBOSE = (
    '"Image Name","PID","Session Name","Session#","Mem Usage",'
    '"Status","User Name","CPU Time","Window Title"\r\n'
    '"chrome.exe","1234","Console","1","120,000 K","Running","DESKTOP\\me","0:00:01","N/A"\r\n'
    '"svchost.exe","567","Services","0","9,000 K","","N/A","0:00:00","N/A"\r\n'
)


def _completed(stdout, returncode=0):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr="")


class TestEvidenceCleaning(unittest.TestCase):
    def test_real_values_pass_through(self):
        self.assertEqual(_clean_tasklist_field("Running"), "Running")
        self.assertEqual(_clean_tasklist_field("DESKTOP\\me"), "DESKTOP\\me")

    def test_missing_or_unknown_become_unavailable(self):
        for value in (None, "", "   ", "N/A", "Unknown"):
            with self.subTest(value=value):
                self.assertEqual(_clean_tasklist_field(value), "Unavailable")

    def test_never_invents_a_running_status(self):
        # The regression replaced absent Status data with a constant.
        self.assertNotEqual(_clean_tasklist_field(None), "Running")
        self.assertNotEqual(_clean_tasklist_field(""), "Running")


class TestTasklistInvocation(unittest.TestCase):
    def test_verbose_flag_is_always_present(self):
        for mode in PROCESS_COLLECTOR_MODES:
            with self.subTest(mode=mode):
                with mock.patch.object(system_service.subprocess, "run",
                                       return_value=_completed(CSV_WITH_VERBOSE)) as run:
                    collect_windows_processes(mode=mode)
                args = run.call_args[0][0]
                self.assertIn("/V", args,
                              "/V is required for User Name and Status")

    def test_parses_user_and_status_from_verbose_output(self):
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed(CSV_WITH_VERBOSE)):
            result = collect_windows_processes()
        self.assertEqual(result["status"], "SUCCESS")
        chrome = result["processes"][0]
        self.assertEqual(chrome["name"], "chrome.exe")
        self.assertEqual(chrome["pid"], "1234")
        self.assertEqual(chrome["user"], "DESKTOP\\me")
        self.assertEqual(chrome["status"], "Running")

    def test_missing_columns_report_unavailable_not_a_guess(self):
        # Same rows without the /V columns.
        csv_no_verbose = (
            '"Image Name","PID","Session Name","Session#","Mem Usage"\r\n'
            '"chrome.exe","1234","Console","1","120,000 K"\r\n'
        )
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed(csv_no_verbose)):
            result = collect_windows_processes()
        row = result["processes"][0]
        self.assertEqual(row["user"], "Unavailable")
        self.assertEqual(row["status"], "Unavailable")

    def test_rows_without_pid_or_name_are_skipped(self):
        csv = (
            '"Image Name","PID"\r\n'
            '"good.exe","1"\r\n'
            '"","2"\r\n'
            '"nameless.exe",""\r\n'
        )
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed(csv)):
            result = collect_windows_processes()
        self.assertEqual([p["name"] for p in result["processes"]], ["good.exe"])


class TestCollectorTiers(unittest.TestCase):
    def test_standard_mode_skips_the_fallback(self):
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed(CSV_WITH_VERBOSE)):
            with mock.patch.object(
                    system_service,
                    "_collect_windows_processes_toolhelp") as fallback:
                result = collect_windows_processes(mode="standard")
        fallback.assert_not_called()
        self.assertEqual(result["collector"], "tasklist")

    def test_failure_falls_back_to_toolhelp(self):
        fallback_result = {"status": "SUCCESS", "processes": [
            {"pid": "9", "name": "x.exe", "executable": "Unavailable",
             "user": "Unavailable", "status": "Unavailable"}],
            "collector": "toolhelp32"}
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed("", returncode=1)):
            with mock.patch.object(
                    system_service,
                    "_collect_windows_processes_toolhelp",
                    return_value=fallback_result):
                result = collect_windows_processes(
                    mode=DEFAULT_PROCESS_COLLECTOR_MODE)
        self.assertEqual(result["collector"], "toolhelp32")

    def test_timeout_triggers_fallback(self):
        import subprocess as real_subprocess
        with mock.patch.object(system_service.subprocess, "run",
                               side_effect=real_subprocess.TimeoutExpired("tasklist", 10)):
            with mock.patch.object(
                    system_service,
                    "_collect_windows_processes_toolhelp",
                    return_value={"status": "UNAVAILABLE", "processes": []}) as fb:
                result = collect_windows_processes()
        fb.assert_called_once()
        self.assertEqual(result["status"], "UNAVAILABLE")

    def test_wmi_mode_enriches_executable_path(self):
        wmi_output = "1234|C:\\Program Files\\Chrome\\chrome.exe\r\n"
        fallback_result = {"status": "SUCCESS", "processes": [
            {"pid": "1234", "name": "chrome.exe", "executable": "Unavailable",
             "user": "Unavailable", "status": "Unavailable"}],
            "collector": "toolhelp32"}

        def fake_run(cmd, *args, **kwargs):
            if "tasklist" in cmd[0]:
                return _completed("", returncode=1)
            return _completed(wmi_output)

        with mock.patch.object(system_service.subprocess, "run",
                               side_effect=fake_run):
            with mock.patch.object(
                    system_service,
                    "_collect_windows_processes_toolhelp",
                    return_value=fallback_result):
                result = collect_windows_processes(mode="wmi")
        self.assertEqual(
            result["processes"][0]["executable"],
            "C:\\Program Files\\Chrome\\chrome.exe")

    def test_wmi_failure_leaves_executable_unavailable(self):
        fallback_result = {"status": "SUCCESS", "processes": [
            {"pid": "1234", "name": "chrome.exe", "executable": "Unavailable",
             "user": "Unavailable", "status": "Unavailable"}],
            "collector": "toolhelp32"}

        def fake_run(cmd, *args, **kwargs):
            if "tasklist" in cmd[0]:
                return _completed("", returncode=1)
            return _completed("", returncode=1)

        with mock.patch.object(system_service.subprocess, "run",
                               side_effect=fake_run):
            with mock.patch.object(
                    system_service,
                    "_collect_windows_processes_toolhelp",
                    return_value=fallback_result):
                result = collect_windows_processes(mode="wmi")
        self.assertEqual(result["processes"][0]["executable"], "Unavailable")

    def test_unknown_mode_falls_back_to_default(self):
        with mock.patch.object(system_service.subprocess, "run",
                               return_value=_completed(CSV_WITH_VERBOSE)):
            result = collect_windows_processes(mode="not-a-mode")
        self.assertEqual(result["status"], "SUCCESS")


class TestRouter(unittest.TestCase):
    def test_router_passes_mode_to_windows_collector(self):
        with mock.patch.object(system_service.platform, "system",
                               return_value="Windows"):
            with mock.patch.object(system_service, "collect_windows_processes",
                                   return_value={"status": "SUCCESS",
                                                 "processes": []}) as win:
                system_service.get_running_processes(mode="wmi")
        win.assert_called_once_with(mode="wmi")

    def test_linux_router_ignores_mode(self):
        with mock.patch.object(system_service.platform, "system",
                               return_value="Linux"):
            with mock.patch.object(system_service, "collect_linux_processes",
                                   return_value={"status": "SUCCESS",
                                                 "processes": []}) as linux:
                system_service.get_running_processes(mode="wmi")
        linux.assert_called_once_with()

    def test_unknown_platform_is_unavailable(self):
        with mock.patch.object(system_service.platform, "system",
                               return_value="Plan9"):
            result = system_service.get_running_processes()
        self.assertEqual(result["status"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()

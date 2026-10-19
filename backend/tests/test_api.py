"""API tests: input validation, honest errors, and the counters clients read.

The backend is imported through ``backend_imports`` so this suite can never
shadow the desktop package that also goes by the name ``app``.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

from backend_imports import backend_path, load_backend_app  # noqa: E402

with backend_path():
    from services import limits
    from services.limits import AnalysisTimeout, ServerBusy, limited_analysis

backend_app = load_backend_app()


SERVICE_RESULT = {
    "username": "target",
    "status": "FOUND",
    "message": "Confirmed 1 profile(s). 1 further candidate(s) could not be verified.",
    "results": [
        {"platform": "GitHub", "status": "FOUND",
         "profile_url": "https://github.com/target",
         "verification": "confirmed", "http_status": 200},
        {"platform": "Reddit", "status": "FOUND",
         "profile_url": "https://reddit.com/u/target",
         "verification": "inconclusive", "http_status": 200},
    ],
    "candidates_count": 2,
    "checked_count": 2,
    "confirmed_count": 1,
    "inconclusive_count": 1,
    "not_found_count": 0,
    "verification_enabled": True,
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:00:04Z",
}


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(backend_app.app)


class TestRoot(ApiTestCase):
    def test_root_reports_the_service(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("running", response.json()["message"])


class TestAnalyzeValidation(ApiTestCase):
    def test_unknown_type_is_rejected_with_a_readable_message(self):
        response = self.client.post("/analyze",
                                    json={"type": "phone", "value": "12345"})
        self.assertEqual(response.status_code, 400)
        body = response.json()
        self.assertEqual(body["status"], "ERROR")
        self.assertEqual(body["message"], "Type must be 'username' or 'email'.")

    def test_empty_value_is_rejected(self):
        response = self.client.post("/analyze",
                                    json={"type": "username", "value": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("username or email", response.json()["message"])

    def test_overlong_value_is_rejected(self):
        response = self.client.post("/analyze",
                                    json={"type": "email", "value": "a" * 300})
        self.assertEqual(response.status_code, 400)
        self.assertIn("too long", response.json()["message"])

    def test_validation_error_uses_a_status_field_not_a_traceback(self):
        response = self.client.post("/analyze", json={})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("detail", response.json())


class TestAnalyzeUsername(ApiTestCase):
    def test_counts_come_from_the_service(self):
        async def fake_check(username, **kwargs):
            return SERVICE_RESULT

        with patch("services.analyzer.check_username", fake_check):
            response = self.client.post(
                "/analyze", json={"type": "username", "value": "target"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["confirmed_count"], 1)
        self.assertEqual(body["inconclusive_count"], 1)
        self.assertEqual(body["unknown_count"], 1)
        # platform_count means "platforms checked", not "profiles found".
        self.assertEqual(body["platform_count"], 2)
        self.assertEqual(body["profiles_found"], 2)
        self.assertEqual(body["status"], "FOUND")
        self.assertIn("confirmed", body["score_basis"].lower())
        self.assertEqual(len(body["results"]), 2)

    def test_unconfirmed_only_lookup_is_never_reported_as_found(self):
        unverified = dict(SERVICE_RESULT, status="UNKNOWN", confirmed_count=0,
                          inconclusive_count=2, checked_count=2,
                          message="No candidate could be confirmed.")

        async def fake_check(username, **kwargs):
            return unverified

        with patch("services.analyzer.check_username", fake_check):
            response = self.client.post(
                "/analyze", json={"type": "username", "value": "target"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "UNKNOWN")
        self.assertEqual(body["confirmed_count"], 0)
        self.assertEqual(body["exposure_score"], 0)

    def test_invalid_handle_is_refused_by_the_service(self):
        response = self.client.post(
            "/analyze", json={"type": "username", "value": "bad handle"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ERROR")
        self.assertIn("may only contain", body["message"])


class TestUsernameRoute(ApiTestCase):
    def test_bad_handle_is_rejected_before_any_work(self):
        response = self.client.get("/username/bad%20handle")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["status"], "ERROR")

    def test_option_like_handle_is_rejected(self):
        response = self.client.get("/username/-tor")
        self.assertEqual(response.status_code, 400)

    def test_valid_handle_runs_the_service(self):
        async def fake_check(username, **kwargs):
            return {"username": username, "status": "NOT_FOUND",
                    "message": "No profiles found.", "results": [],
                    "confirmed_count": 0, "inconclusive_count": 0}

        with patch("routes.username.check_username", fake_check):
            response = self.client.get("/username/target")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "NOT_FOUND")


class TestServerLimits(ApiTestCase):
    def test_busy_server_says_so_instead_of_queueing(self):
        with patch.object(limits, "_slots", asyncio.Semaphore(0)):
            response = self.client.post(
                "/analyze", json={"type": "username", "value": "target"})
        self.assertEqual(response.status_code, 429)
        body = response.json()
        self.assertEqual(body["status"], "ERROR")
        self.assertIn("already running", body["message"].lower())

    def test_analysis_timeout_is_reported_as_a_timeout(self):
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def failing_limits(timeout=None):
            raise AnalysisTimeout("The analysis took too long and was stopped.")
            yield  # pragma: no cover

        with patch.object(backend_app, "limited_analysis", failing_limits):
            response = self.client.post(
                "/analyze", json={"type": "username", "value": "target"})

        self.assertEqual(response.status_code, 504)
        self.assertIn("too long", response.json()["message"])


class TestLimitPrimitives(unittest.TestCase):
    def test_busy_slot_is_refused(self):
        async def scenario():
            with patch.object(limits, "_slots", asyncio.Semaphore(0)):
                with self.assertRaises(ServerBusy):
                    async with limited_analysis(timeout=5):
                        pass

        asyncio.run(scenario())

    def test_slot_is_released_after_a_failure(self):
        async def scenario():
            with patch.object(limits, "_slots", asyncio.Semaphore(1)):
                with self.assertRaises(ValueError):
                    async with limited_analysis(timeout=5):
                        raise ValueError("boom")
                # The slot must be free again, or one bad scan would wedge
                # the server forever.
                async with limited_analysis(timeout=5):
                    return True

        self.assertTrue(asyncio.run(scenario()))

    def test_two_slots_are_exclusive(self):
        async def scenario():
            with patch.object(limits, "_slots", asyncio.Semaphore(1)):
                async with limited_analysis(timeout=5):
                    with self.assertRaises(ServerBusy):
                        async with limited_analysis(timeout=5):
                            pass

        asyncio.run(scenario())

    def test_long_analysis_is_stopped_by_the_backstop(self):
        async def scenario():
            with patch.object(limits, "_slots", asyncio.Semaphore(1)):
                with self.assertRaises(AnalysisTimeout):
                    async with limited_analysis(timeout=0.05):
                        await asyncio.sleep(5)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()

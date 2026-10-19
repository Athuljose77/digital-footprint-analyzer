"""Tests for the username service: validation, discovery, and verification.

Everything here is offline. The verification layer takes an injectable page
fetcher, so "the platform answered 200 with a login page" and "the request
timed out" are ordinary test inputs, not network conditions.

The backend directory is only on ``sys.path`` while these modules import, so
the desktop's ``app`` package cannot be shadowed by ``backend/app.py``.
"""

import asyncio
import os
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend_imports import backend_path  # noqa: E402

with backend_path():
    from services import username_service as us
    from services.username_service import (
        CONFIRMED,
        INCONCLUSIVE,
        NOT_FOUND,
        Candidate,
        FetchOutcome,
        check_username,
        classify,
        parse_candidates,
        verify_candidates,
    )

SHERLOCK_OUTPUT = """
[*] Checking username target on:
[+] GitHub: https://github.com/target
[+] Twitter: https://twitter.com/target
[+] Reddit: https://www.reddit.com/user/target
[-] Example: https://example.com/not-a-profile
Try OSINTSearch! https://osint.search
"""


def completed_process(stdout=SHERLOCK_OUTPUT, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=["sherlock"], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeFetcher:
    """Async fetcher returning canned outcomes, recording every call."""

    def __init__(self, outcomes=None, error=None, delay=0.0):
        self.outcomes = dict(outcomes or {})
        self.error = error
        self.delay = delay
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def __call__(self, url, timeout):
        self.calls.append(url)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.error is not None:
                raise self.error
            outcome = self.outcomes.get(url)
            if outcome is None:
                return FetchOutcome(status=200, final_url=url, body="")
            return outcome
        finally:
            self.in_flight -= 1


def page(url, status=200, body="", final_url=None, failure="", note=""):
    return FetchOutcome(status=status, final_url=final_url or url, body=body,
                        failure=failure, note=note)


class TestValidation(unittest.TestCase):
    def test_accepts_realistic_handles(self):
        for handle in ("target", "a", "user.name", "user_name", "user-name",
                       "User123", "a" * 64):
            with self.subTest(handle=handle):
                self.assertEqual(us.validate_username(handle), "")

    def test_rejects_empty(self):
        self.assertIn("empty", us.validate_username("   "))

    def test_rejects_too_long(self):
        self.assertIn("too long", us.validate_username("a" * 65))

    def test_rejects_option_like_and_unsafe_handles(self):
        for handle in ("-flag", "--tor", "-", "bad handle", "user/name",
                       "user?x=1", "user#frag", "user@host", "café",
                       "user;rm", "$(whoami)", "user\nname", ".dot"):
            with self.subTest(handle=handle):
                self.assertNotEqual(us.validate_username(handle), "")

    def test_pattern_keeps_length_limit_in_step_with_constant(self):
        self.assertEqual(us.USERNAME_MAX_LENGTH, 64)


class TestSherlockInvocation(unittest.TestCase):
    def test_invalid_handle_never_starts_a_process(self):
        with patch.object(us.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                us.run_sherlock("-oops")
        run.assert_not_called()

    def test_handle_is_separated_and_never_shelled(self):
        with patch.object(us.subprocess, "run") as run:
            run.return_value = completed_process()
            us.run_sherlock("target", timeout=12)
        command = run.call_args.args[0]
        self.assertIn("sherlock_project", command)
        separator = command.index("--")
        self.assertEqual(command[separator + 1], "target")
        self.assertEqual(command[separator + 2:], [])
        kwargs = run.call_args.kwargs
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 12.0)

    def test_timeout_is_clamped(self):
        self.assertEqual(us._clamp_timeout(None), us.SHERLOCK_TIMEOUT_SECONDS)
        self.assertEqual(us._clamp_timeout(0.0001), us.MIN_TIMEOUT_SECONDS)
        self.assertEqual(us._clamp_timeout(10 ** 9), us.MAX_TIMEOUT_SECONDS)
        self.assertEqual(us._clamp_timeout("nonsense"), us.SHERLOCK_TIMEOUT_SECONDS)


class TestParsing(unittest.TestCase):
    def test_extracts_only_profile_urls(self):
        candidates = parse_candidates(SHERLOCK_OUTPUT)
        self.assertEqual([c.platform for c in candidates],
                         ["GitHub", "Twitter", "Reddit"])
        self.assertEqual(candidates[0].url, "https://github.com/target")

    def test_drops_homepages_search_and_account_pages(self):
        output = "\n".join([
            "[+] Homepage: https://example.com/",
            "[+] SearchThing: https://example.com/search?q=target",
            "[+] Query: https://example.com/?query=target",
            "[+] Api: https://example.com/api/users/target",
            "[+] Wiki: https://en.wikipedia.org/wiki/Special:CentralAuth/target",
            "[+] Real: https://example.com/users/target",
            "[-] Gone: https://example.com/gone/target",
        ])
        candidates = parse_candidates(output)
        self.assertEqual([c.url for c in candidates],
                         ["https://example.com/users/target"])

    def test_collapses_duplicate_urls(self):
        output = "\n".join([
            "[+] One: https://example.com/target",
            "[+] Two: https://example.com/target",
        ])
        self.assertEqual(len(parse_candidates(output)), 1)

    def test_platform_falls_back_to_hostname(self):
        self.assertEqual(us.extract_platform("weird line", "https://host.test/x"),
                         "host.test")


class TestAddressGuard(unittest.TestCase):
    def test_public_addresses_are_allowed(self):
        for address in ("93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.assertTrue(us.is_public_address(address))

    def test_internal_addresses_are_refused(self):
        for address in ("127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1",
                        "169.254.169.254", "::1", "fd00::1", "fe80::1", "0.0.0.0",
                        "100.64.0.1", "198.18.0.1", "not-an-ip"):
            with self.subTest(address=address):
                self.assertFalse(us.is_public_address(address))

    def test_url_guard_refuses_internal_and_odd_urls(self):
        for url, expected in (
            ("http://127.0.0.1/profile", "local"),
            ("http://[::1]/profile", "local"),
            ("http://localhost/profile", "local"),
            ("http://router.local/profile", "local"),
            ("ftp://example.com/profile", "http"),
            ("file:///etc/passwd", "http"),
            ("https://user:pass@example.com/profile", "credentials"),
            ("https://example.com:8080/profile", "port"),
        ):
            with self.subTest(url=url):
                self.assertIn(expected, us.url_block_reason(url))

    def test_host_guard_uses_every_resolved_address(self):
        def fake_getaddrinfo(host, *args, **kwargs):
            if host == "mixed.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.9", 0))]
            if host == "public.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
            raise OSError("name or service not known")

        with patch.object(us.socket, "getaddrinfo", fake_getaddrinfo):
            self.assertEqual(us.host_block_reason("public.test"), "")
            self.assertIn("local network", us.host_block_reason("mixed.test"))
            self.assertIn("resolved", us.host_block_reason("unknown.test"))

    def test_default_fetcher_refuses_internal_host_without_connecting(self):
        def fake_getaddrinfo(host, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

        def no_client(*args, **kwargs):
            raise AssertionError("no HTTP client may be created for a LAN host")

        with patch.object(us.socket, "getaddrinfo", fake_getaddrinfo), \
                patch.object(us.httpx, "AsyncClient", no_client):
            outcome = asyncio.run(us.default_fetcher("http://profile.test/target", 1.0))

        self.assertEqual(outcome.failure, "blocked")
        self.assertIn("local network", outcome.note)

    def test_default_fetcher_refuses_redirects_to_internal_hosts(self):
        calls = []

        class FakeResponse:
            def __init__(self):
                self.status_code = 302
                self.headers = {"location": "http://127.0.0.1/admin",
                                "content-type": "text/html"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            async def aiter_bytes(self):
                yield b"<html>redirecting</html>"

        class FakeStream:
            def __init__(self, response):
                self.response = response

            async def __aenter__(self):
                return self.response

            async def __aexit__(self, *args):
                return False

        class FakeClient:
            def stream(self, method, url):
                calls.append(url)
                return FakeStream(FakeResponse())

            async def aclose(self):
                pass

        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, *args, **kwargs):
            if host == "profile.test":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                         ("93.184.216.34", 0))]
            return real_getaddrinfo(host, *args, **kwargs)

        with patch.object(us.socket, "getaddrinfo", fake_getaddrinfo):
            outcome = asyncio.run(us.default_fetcher(
                "http://profile.test/target", 1.0, client=FakeClient()))

        self.assertEqual(calls, ["http://profile.test/target"])
        self.assertEqual(outcome.failure, "blocked")
        self.assertIn("local network", outcome.note)


class TestClassification(unittest.TestCase):
    """The rules that decide what a fetched page proves."""

    handle = "target"
    url = "https://github.com/target"

    def test_page_showing_the_handle_is_confirmed(self):
        outcome = page(self.url, body="<html><h1>target</h1></html>")
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, CONFIRMED)
        self.assertIn("shows this handle", note)

    def test_handle_in_a_meta_tag_counts_as_confirmed(self):
        outcome = page(self.url, body=(
            '<html><head><meta property="og:title" content="target"></head>'
            "<body>app shell</body></html>"))
        self.assertEqual(classify(outcome, self.url, self.handle)[0], CONFIRMED)

    def test_http_200_without_the_handle_is_inconclusive(self):
        outcome = page(self.url, body="<html><body>Welcome</body></html>")
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, INCONCLUSIVE)
        self.assertIn("does not mention this handle", note)

    def test_redirect_away_from_the_profile_is_inconclusive(self):
        outcome = page(self.url, final_url="https://example.com/login",
                       body="<html><body>target</body></html>")
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, INCONCLUSIVE)
        self.assertIn("redirected away", note)

    def test_sign_in_wall_is_inconclusive_never_confirmed(self):
        outcome = page(self.url, body="<html><body>Sign in to continue</body></html>")
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, INCONCLUSIVE)
        self.assertIn("sign-in", note)

    def test_page_text_saying_missing_means_not_found(self):
        outcome = page(self.url, body=(
            "<html><body>Sorry, this page isn't available</body></html>"))
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, NOT_FOUND)
        self.assertIn("does not exist", note)

    def test_missing_text_inside_scripts_is_ignored(self):
        outcome = page(self.url, body=(
            '<script>var e = "user not found";</script><h1>target</h1>'))
        self.assertEqual(classify(outcome, self.url, self.handle)[0], CONFIRMED)

    def test_http_404_and_410_are_not_found(self):
        for status in (404, 410):
            with self.subTest(status=status):
                outcome = page(self.url, status=status, body="gone")
                self.assertEqual(classify(outcome, self.url, self.handle)[0],
                                 NOT_FOUND)

    def test_protected_pages_are_inconclusive(self):
        for status in (401, 403):
            with self.subTest(status=status):
                outcome = page(self.url, status=status)
                verification, note = classify(outcome, self.url, self.handle)
                self.assertEqual(verification, INCONCLUSIVE)
                self.assertIn("sign-in", note)

    def test_rate_limit_is_inconclusive_and_named(self):
        outcome = page(self.url, status=429)
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, INCONCLUSIVE)
        self.assertIn("rate-limited", note)

    def test_server_errors_are_inconclusive(self):
        for status in (500, 503):
            with self.subTest(status=status):
                outcome = page(self.url, status=status)
                self.assertEqual(classify(outcome, self.url, self.handle)[0],
                                 INCONCLUSIVE)

    def test_timeout_is_inconclusive_not_missing(self):
        outcome = FetchOutcome(final_url=self.url, failure="timeout",
                               note="Not fetched: the request timed out.")
        verification, note = classify(outcome, self.url, self.handle)
        self.assertEqual(verification, INCONCLUSIVE)
        self.assertIn("timed out", note)

    def test_blocked_and_dns_failures_are_inconclusive(self):
        for failure in ("blocked", "dns", "tls", "connection", "network", "error"):
            with self.subTest(failure=failure):
                outcome = FetchOutcome(final_url=self.url, failure=failure)
                verification, note = classify(outcome, self.url, self.handle)
                self.assertEqual(verification, INCONCLUSIVE)
                self.assertTrue(note)

    def test_redirect_left_unfollowed_is_inconclusive(self):
        outcome = page(self.url, status=302, final_url=self.url)
        self.assertEqual(classify(outcome, self.url, self.handle)[0],
                         INCONCLUSIVE)


class TestVerificationPass(unittest.TestCase):
    def candidates(self, count):
        return [Candidate(platform=f"P{i}", url=f"https://p{i}.test/target")
                for i in range(count)]

    def test_one_fetch_per_candidate_no_more_than_the_limit(self):
        fetcher = FakeFetcher()
        records = asyncio.run(verify_candidates(self.candidates(45), "target",
                                                fetcher))
        self.assertEqual(len(fetcher.calls), us.MAX_VERIFY_CANDIDATES)
        self.assertEqual(len(records), 45)
        skipped = [r for r in records if "per-scan limit" in r["verification_note"]]
        self.assertEqual(len(skipped), 5)
        self.assertFalse(any(r["checked"] for r in skipped))

    def test_concurrency_is_bounded(self):
        fetcher = FakeFetcher(delay=0.01)
        asyncio.run(verify_candidates(self.candidates(20), "target", fetcher,
                                      concurrency=5))
        self.assertLessEqual(fetcher.max_in_flight, 5)
        self.assertGreaterEqual(fetcher.max_in_flight, 2)

    def test_budget_bounds_the_whole_pass(self):
        fetcher = FakeFetcher(delay=0.05)
        records = asyncio.run(verify_candidates(self.candidates(40), "target",
                                                fetcher, budget=0.2))
        self.assertEqual(len(records), 40)
        self.assertTrue(any("budget ran out" in r["verification_note"]
                            for r in records))
        self.assertLessEqual(len(fetcher.calls), 40)

    def test_fetcher_failures_keep_every_candidate(self):
        fetcher = FakeFetcher(error=RuntimeError("boom"))
        records = asyncio.run(verify_candidates(self.candidates(3), "target",
                                                fetcher))
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertEqual(record["verification"], INCONCLUSIVE)
            self.assertIn("RuntimeError", record["verification_note"])

    def test_every_record_carries_provenance(self):
        url = "https://p0.test/target"
        fetcher = FakeFetcher({url: page(url, body="<h1>target</h1>")})
        record = asyncio.run(verify_candidates(self.candidates(1), "target",
                                               fetcher))[0]
        self.assertEqual(record["profile_url"], url)
        self.assertEqual(record["final_url"], url)
        self.assertEqual(record["http_status"], 200)
        self.assertTrue(record["checked"])
        self.assertTrue(str(record["checked_at"]).endswith("Z"))


class TestCheckUsername(unittest.TestCase):
    def run_check(self, fetcher=None, stdout=SHERLOCK_OUTPUT, returncode=0,
                  stderr="", exc=None, **kwargs):
        def fake_run(username, timeout=None):
            self.seen_timeout = timeout
            if exc is not None:
                raise exc
            return completed_process(stdout, returncode, stderr)

        with patch.object(us, "run_sherlock", side_effect=fake_run):
            return asyncio.run(check_username("target", fetcher=fetcher, **kwargs))

    def confirming_fetcher(self):
        outcomes = {}
        for platform_url in ("https://github.com/target", "https://twitter.com/target",
                             "https://www.reddit.com/user/target"):
            outcomes[platform_url] = page(platform_url, body="<h1>target</h1>")
        return FakeFetcher(outcomes)

    def test_invalid_handle_is_refused_before_any_work(self):
        result = self.run_check()
        invalid = asyncio.run(check_username("bad handle"))
        self.assertEqual(invalid["status"], "ERROR")
        self.assertIn("may only contain", invalid["message"])
        self.assertEqual(invalid["results"], [])

    def test_confirmed_profiles_are_reported_as_confirmed(self):
        fetcher = self.confirming_fetcher()
        result = self.run_check(fetcher=fetcher)
        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(result["confirmed_count"], 3)
        self.assertEqual(result["inconclusive_count"], 0)
        self.assertEqual(result["checked_count"], 3)
        self.assertEqual(len(result["results"]), 3)
        self.assertTrue(all(r["verification"] == CONFIRMED for r in result["results"]))
        self.assertTrue(str(result["started_at"]).endswith("Z"))
        self.assertTrue(str(result["finished_at"]).endswith("Z"))

    def test_generic_pages_are_candidates_not_confirmed_profiles(self):
        fetcher = FakeFetcher()
        result = self.run_check(fetcher=fetcher)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["confirmed_count"], 0)
        self.assertEqual(result["inconclusive_count"], 3)
        self.assertEqual(len(result["results"]), 3)
        self.assertNotIn("Confirmed 1", result["message"])

    def test_unconfirmed_results_are_never_labelled_confirmed(self):
        fetcher = FakeFetcher()
        result = self.run_check(fetcher=fetcher)
        for entry in result["results"]:
            self.assertEqual(entry["verification"], INCONCLUSIVE)
            self.assertIn("does not mention this handle",
                          entry["verification_note"])

    def test_missing_profiles_are_not_reported_as_results(self):
        outcomes = {}
        for platform_url in ("https://github.com/target", "https://twitter.com/target",
                             "https://www.reddit.com/user/target"):
            outcomes[platform_url] = page(platform_url, status=404, body="gone")
        result = self.run_check(fetcher=FakeFetcher(outcomes))
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["not_found_count"], 3)
        self.assertEqual(result["checked_count"], 3)

    def test_mixed_results_report_both_counts(self):
        outcomes = {
            "https://github.com/target": page("https://github.com/target",
                                              body="<h1>target</h1>"),
        }
        result = self.run_check(fetcher=FakeFetcher(outcomes))
        self.assertEqual(result["status"], "FOUND")
        self.assertEqual(result["confirmed_count"], 1)
        self.assertEqual(result["inconclusive_count"], 2)
        self.assertIn("could not be verified", result["message"])

    def test_verification_disabled_makes_no_requests(self):
        fetcher = FakeFetcher()
        result = self.run_check(fetcher=fetcher, verify=False)
        self.assertEqual(fetcher.calls, [])
        self.assertEqual(result["status"], "FOUND")
        self.assertFalse(result["verification_enabled"])
        self.assertEqual(result["checked_count"], 0)
        self.assertTrue(all(r["verification"] == INCONCLUSIVE
                            for r in result["results"]))
        self.assertIn("turned off", result["message"])

    def test_sherlock_timeout_is_reported_as_unknown(self):
        result = self.run_check(exc=subprocess.TimeoutExpired(cmd="sherlock", timeout=1))
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIn("timed out", result["message"])
        self.assertEqual(result["results"], [])

    def test_sherlock_failure_is_reported_with_its_message(self):
        result = self.run_check(returncode=2, stderr="module not found")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["message"], "module not found")

    def test_unexpected_exception_is_reported_without_leaking_details(self):
        result = self.run_check(exc=RuntimeError("boom"))
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("RuntimeError", result["message"])

    def test_timeout_argument_reaches_sherlock(self):
        self.run_check(fetcher=FakeFetcher(), timeout=15)
        self.assertEqual(self.seen_timeout, 15)

    def test_no_candidates_found(self):
        result = self.run_check(stdout="[*] Checking username target on:\n",
                                fetcher=FakeFetcher())
        self.assertEqual(result["status"], "NOT_FOUND")
        self.assertEqual(result["candidates_count"], 0)
        self.assertEqual(result["results"], [])


if __name__ == "__main__":
    unittest.main()

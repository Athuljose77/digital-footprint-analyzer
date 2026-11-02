"""Username discovery *and* verification.

Sherlock reports a hit whenever a platform answers with something other than
its "this user does not exist" marker. That is a **candidate**, not proof:
plenty of sites answer HTTP 200 for any handle, redirect unknown users to a
sign-in page, or serve a generic shell. Treating those as confirmed profiles is
the classic false positive in username tooling, so this module adds a small
verification layer of its own.

What this module guarantees:

* **No argument injection.** The handle is validated against a conservative
  pattern, rejected if it could be read as an option, and passed as a single
  argv element after ``--``; no shell is ever involved.
* **A hit is only a candidate.** Every Sherlock line is verified (or not) by
  fetching the page once and checking what the platform actually returned.
  HTTP 200 alone is never treated as proof.
* **Bounded, polite work.** At most one request per candidate, at most
  ``VERIFY_CONCURRENCY`` in flight, capped body size, and both a per-request
  and a whole-pass deadline. Requests are unauthenticated and identifiable.
* **Honest outcomes.** Each candidate ends up ``confirmed``, ``inconclusive``
  or ``not_found``, with the HTTP status, the final URL, a plain-language note
  and the time of the check. Failures (timeouts, DNS, TLS, rate limits,
  private addresses) are reported as such, never as a missing profile.
"""

import asyncio
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

import httpx


# ------------------------------------------------------------------ limits --

# Overall budget for the Sherlock subprocess. Kept under its historical name so
# existing callers are unaffected.
TIMEOUT_SECONDS = 90
SHERLOCK_TIMEOUT_SECONDS = TIMEOUT_SECONDS
SHERLOCK_SITE_TIMEOUT = 10
MIN_TIMEOUT_SECONDS = 1.0
MAX_TIMEOUT_SECONDS = 300.0

# Handles are alphanumeric with the separators platforms actually allow. The
# first character must be alphanumeric, so a handle can never start with "-"
# and be mistaken for an option.
USERNAME_MAX_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Verification pass bounds. One request per candidate, five at a time, with a
# hard cap on how many candidates are fetched at all.
MAX_VERIFY_CANDIDATES = 40
VERIFY_CONCURRENCY = 5
VERIFY_REQUEST_TIMEOUT = 8.0
VERIFY_BUDGET_SECONDS = 30.0
MAX_BODY_BYTES = 256_000
MAX_REDIRECT_HOPS = 4
ALLOWED_PORTS = (None, 80, 443)
USER_AGENT = (
    "DigitalFootprintAnalyzer/1.0 (local, unauthenticated profile check)"
)

# Outcome vocabulary for one candidate.
CONFIRMED = "confirmed"
INCONCLUSIVE = "inconclusive"
NOT_FOUND = "not_found"

# Phrases that mean "this account does not exist". They are only trusted when
# they appear as page text, not inside scripts, because bundle code contains
# such strings for unrelated reasons.
MISSING_MARKERS = (
    "user not found",
    "account not found",
    "profile not found",
    "page not found",
    "no longer available",
    "sorry, this page isn't available",
    "this page doesn't exist",
    "this account doesn't exist",
    "we couldn't find that page",
    "unknown user",
    "404 not found",
)

# Phrases that mean "you are looking at a sign-in wall, not a profile".
LOGIN_MARKERS = (
    "sign in to continue",
    "log in to continue",
    "please sign in",
    "please log in",
    "create an account to continue",
)

_SCRIPT_RE = re.compile(
    r"<(script|style|noscript)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")

VISIBLE_TEXT_LIMIT = 20_000


# ------------------------------------------------------------------- types --


@dataclass
class Candidate:
    """One platform hit reported by the discovery tool."""

    platform: str
    url: str


@dataclass
class FetchOutcome:
    """What came back from one page request."""

    status: Optional[int] = None
    final_url: str = ""
    body: str = ""
    failure: str = ""
    note: str = ""
    redirects: int = 0


@dataclass
class VerificationSummary:
    """Counters for one verification pass, used for honest reporting."""

    candidates: int = 0
    checked: int = 0
    confirmed: int = 0
    inconclusive: int = 0
    not_found: int = 0
    skipped: int = 0
    details: List[dict] = field(default_factory=list)


Fetcher = Callable[[str, float], Awaitable[FetchOutcome]]


# -------------------------------------------------------------- validation --


def validate_username(username: str) -> str:
    """Return "" when *username* is safe to look up, else the reason.

    The pattern is deliberately narrower than what every platform allows: a
    handle that cannot be expressed as ``[A-Za-z0-9._-]`` is not something this
    tool should hand to a subprocess or a URL.
    """

    value = (username or "").strip()
    if not value:
        return "Username cannot be empty."
    if len(value) > USERNAME_MAX_LENGTH:
        return f"Username is too long (limit {USERNAME_MAX_LENGTH} characters)."
    if value.startswith("-"):
        return "Username cannot start with '-'."
    if not USERNAME_PATTERN.match(value):
        return (
            "Username may only contain letters, digits, and the characters "
            "'.', '_' and '-'."
        )
    return ""


# --------------------------------------------------------------- discovery --


def run_sherlock(username: str, timeout: float = None):
    """Run Sherlock for one handle and return the completed process.

    Args:
        username: handle to look up. Validated before use.
        timeout: overall budget in seconds for the subprocess. None uses
            SHERLOCK_TIMEOUT_SECONDS.

    Raises:
        ValueError: the handle failed validation (defence in depth: the caller
            validates first, but this function never trusts its input).
    """

    reason = validate_username(username)
    if reason:
        raise ValueError(reason)

    budget = _clamp_timeout(timeout)

    command = [
        sys.executable,
        "-m",
        "sherlock_project",
        "--print-found",
        "--no-color",
        "--timeout",
        str(SHERLOCK_SITE_TIMEOUT),
        # Everything after "--" is positional, so a handle can never be read
        # as an option even if validation were relaxed later.
        "--",
        username.strip(),
    ]

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=budget,
    )


def _clamp_timeout(timeout: Optional[float]) -> float:
    if timeout is None:
        return SHERLOCK_TIMEOUT_SECONDS
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        return SHERLOCK_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(value, MAX_TIMEOUT_SECONDS))


def parse_candidates(output: str) -> List[Candidate]:
    """Turn Sherlock's stdout into candidate platforms.

    Lines that are not profile URLs (banners, footers, API endpoints, search
    URLs, account-management pages) are dropped, and duplicates are collapsed.
    Nothing here claims a profile exists; that is the verifier's job.
    """

    candidates: List[Candidate] = []
    seen: set = set()

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "http://" not in line and "https://" not in line:
            continue
        if line.startswith("Try OSINTSearch"):
            continue
        # Lines the tool itself marked as not found are not candidates.
        if line.startswith("[-]"):
            continue

        url_match = re.search(r"https?://\S+", line)
        if not url_match:
            continue

        profile_url = url_match.group(0).rstrip(".,)]}>")
        parsed = urlparse(profile_url)

        # Platform homepages are not profiles.
        if parsed.path in ("", "/") and not parsed.query:
            continue

        ignored_url_parts = (
            "/api/",
            "/search",
            "/query",
            "/lookup",
            "/osint-tools/",
            "api.mojang.com",
        )
        url_to_check = (parsed.netloc + parsed.path + "?" + parsed.query).lower()
        if any(part in url_to_check for part in ignored_url_parts):
            continue

        query_lower = parsed.query.lower()
        if (
            "search/" in query_lower
            or "search=" in query_lower
            or "query=" in query_lower
        ):
            continue

        if (
            parsed.netloc.lower() == "en.wikipedia.org"
            and parsed.path.lower().startswith("/wiki/special:centralauth/")
        ):
            continue

        if profile_url in seen:
            continue
        seen.add(profile_url)

        candidates.append(Candidate(
            platform=extract_platform(line, profile_url),
            url=profile_url,
        ))

    return candidates


def extract_platform(line: str, profile_url: str) -> str:
    """Extract the platform name from one Sherlock output line."""

    if ":" in line:
        prefix = re.sub(r"^[\[\]\+\!\*\s]+", "", line.split(":", 1)[0]).strip()
        if prefix:
            return prefix

    try:
        hostname = urlparse(profile_url).hostname
        if hostname:
            return hostname
    except Exception:
        pass

    return "Unknown"


# ------------------------------------------------------- address safety SSRF --


def is_public_address(value: str) -> bool:
    """True only for addresses on the public internet.

    Blocks loopback, private, link-local, multicast, reserved, unspecified and
    carrier-grade NAT ranges, so a profile URL can never be used to probe the
    user's own machine or network.
    """

    import ipaddress

    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False

    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return is_public_address(str(address.ipv4_mapped))
    return bool(address.is_global)


def host_block_reason(host: str) -> str:
    """Return "" when *host* resolves only to public addresses, else why not."""

    name = (host or "").strip().strip("[]").lower()
    if not name:
        return "Not fetched: the URL has no host."
    if (
        name == "localhost"
        or name.endswith(".localhost")
        or name.endswith(".local")
        or name.endswith(".internal")
        or name.endswith(".home.arpa")
    ):
        return "Not fetched: the host is on the local network."

    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return "Not fetched: the host could not be resolved."

    addresses = {info[4][0] for info in infos if info[4]}
    if not addresses:
        return "Not fetched: the host could not be resolved."
    if not all(is_public_address(address) for address in addresses):
        return "Not fetched: the host is on the local network."
    return ""


def url_block_reason(url: str) -> str:
    """Return "" when the URL is safe to fetch, else the refusal note."""

    try:
        parsed = urlparse(url)
    except ValueError:
        return "Not fetched: the URL could not be parsed."
    if parsed.scheme not in ("http", "https"):
        return "Not fetched: only http and https profile URLs are checked."
    if parsed.username or parsed.password:
        return "Not fetched: the URL carries credentials."
    try:
        port = parsed.port
    except ValueError:
        return "Not fetched: the URL has an invalid port."
    if port not in ALLOWED_PORTS:
        return "Not fetched: non-standard ports are not contacted."
    return host_block_reason(parsed.hostname)


# ------------------------------------------------------------------ verify --


async def default_fetcher(
    url: str,
    timeout: float = VERIFY_REQUEST_TIMEOUT,
    *,
    client: Optional[httpx.AsyncClient] = None,
) -> FetchOutcome:
    """Fetch one profile page, read-only and without following anything risky.

    Redirects are followed by hand so every hop is re-checked against the
    address guard, and only a capped amount of text is read.
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
    }
    owns_client = False

    current = url
    redirects = 0
    try:
        while True:
            # Resolving can block briefly; keep the event loop free.
            reason = await asyncio.to_thread(url_block_reason, current)
            if reason:
                return FetchOutcome(final_url=current, failure="blocked",
                                    note=reason, redirects=redirects)
            if client is None:
                # Created only once the address guard has accepted the target,
                # so a LAN address never even gets a client.
                client = httpx.AsyncClient(
                    follow_redirects=False, timeout=timeout, headers=headers)
                owns_client = True
            try:
                async with client.stream("GET", current) as response:
                    status = response.status_code
                    location = response.headers.get("location")
                    body = ""
                    # Only successful pages are read: redirect and error bodies
                    # are never used, so they are not downloaded.
                    if status < 300 and _is_textual(response):
                        body = await _read_capped(response)
            except httpx.TimeoutException:
                return FetchOutcome(final_url=current, failure="timeout",
                                    note="Not fetched: the request timed out.",
                                    redirects=redirects)
            except httpx.HTTPError as error:
                kind = _failure_kind(error)
                return FetchOutcome(final_url=current, failure=kind,
                                    note=_failure_note(kind), redirects=redirects)
            except (OSError, socket.error):
                return FetchOutcome(
                    final_url=current, failure="connection",
                    note=_failure_note("connection"), redirects=redirects)

            if status in (301, 302, 303, 307, 308) and location:
                redirects += 1
                if redirects > MAX_REDIRECT_HOPS:
                    return FetchOutcome(
                        final_url=current, failure="redirect",
                        note="Not fetched: too many redirects.", redirects=redirects)
                current = urljoin(current, location)
                continue

            return FetchOutcome(status=status, final_url=current, body=body,
                                redirects=redirects)
    finally:
        if owns_client and client is not None:
            await client.aclose()


def _is_textual(response: httpx.Response) -> bool:
    content_type = (response.headers.get("content-type") or "").lower()
    if not content_type:
        return True
    return ("text/" in content_type or "html" in content_type
            or "json" in content_type or "xml" in content_type)


async def _read_capped(response: httpx.Response) -> str:
    chunks: List[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        remaining = MAX_BODY_BYTES - size
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        size += min(len(chunk), remaining)
    charset = getattr(response, "charset_encoding", None) or "utf-8"
    try:
        return b"".join(chunks).decode(charset, "replace")
    except LookupError:
        return b"".join(chunks).decode("utf-8", "replace")


def _failure_kind(error: Exception) -> str:
    text = str(error).lower()
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if any(marker in text for marker in (
        "name or service not known",
        "nodename nor servname",
        "temporary failure in name resolution",
        "no address associated",
        "getaddrinfo",
    )):
        return "dns"
    if "certificate" in text or "ssl" in text or "tls" in text:
        return "tls"
    if any(marker in text for marker in ("refused", "reset", "unreachable")):
        return "connection"
    return "network"


def _failure_note(kind: str) -> str:
    return {
        "timeout": "Not fetched: the request timed out.",
        "dns": "Not fetched: the host could not be resolved.",
        "tls": "Not fetched: the secure connection could not be established.",
        "connection": "Not fetched: the connection was refused or dropped.",
        "redirect": "Not fetched: too many redirects.",
        "blocked": "Not fetched: the address is not a public internet address.",
    }.get(kind, "Not fetched: the network request failed.")


def visible_text(body: str, limit: int = VISIBLE_TEXT_LIMIT) -> str:
    """Lower-cased page text with scripts, styles and tags removed."""

    text = _SCRIPT_RE.sub(" ", (body or "")[: MAX_BODY_BYTES * 4])
    text = _TAG_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()[:limit].lower()


def classify(outcome: FetchOutcome, profile_url: str,
             username: str) -> Tuple[str, str]:
    """Decide what a fetched page proves about one candidate.

    Returns ``(verification, note)``. The rule is conservative on purpose: the
    only way to be *confirmed* is for the platform's own page to show the
    handle, and "not found" needs the platform to say so in page text.
    """

    if outcome.failure:
        if outcome.failure == "blocked":
            return INCONCLUSIVE, outcome.note or _failure_note("blocked")
        return INCONCLUSIVE, outcome.note or _failure_note(outcome.failure)

    status = outcome.status
    if status in (404, 410):
        return NOT_FOUND, "The platform answered 'not found' when the page was fetched."
    if status in (401, 403):
        return INCONCLUSIVE, "The platform requires sign-in before the profile can be read and none was used."
    if status == 429:
        return INCONCLUSIVE, "The platform rate-limited the check; nothing was confirmed or denied."
    if status is None or status >= 500:
        return INCONCLUSIVE, "The platform did not return a usable page."
    if 300 <= status < 400:
        return INCONCLUSIVE, "The platform redirected the request without reaching a profile page."

    if 200 <= status < 300:
        final_url = outcome.final_url or profile_url
        if not _url_names_handle(final_url, username):
            return INCONCLUSIVE, "The platform redirected away from the profile URL, so the page could not be attributed to this handle."

        text = visible_text(outcome.body)
        if any(marker in text for marker in MISSING_MARKERS):
            return NOT_FOUND, "The fetched page says this account does not exist."

        body_lower = (outcome.body or "").lower()
        handle_present = username.lower() in body_lower
        if any(marker in text for marker in LOGIN_MARKERS) and not handle_present:
            return INCONCLUSIVE, "The fetched page was a sign-in wall, not the profile."
        if handle_present:
            return CONFIRMED, "The platform page itself shows this handle."
        return INCONCLUSIVE, "The page was fetched but does not mention this handle; it may need scripts to render."

    return INCONCLUSIVE, f"The platform answered HTTP {status}."


def _url_names_handle(url: str, username: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    identifiers = (parsed.path + "?" + parsed.query).lower()
    return username.lower() in identifiers


def candidate_result(candidate: Candidate, verification: str, note: str,
                     outcome: Optional[FetchOutcome] = None,
                     checked: bool = False) -> Dict[str, object]:
    """Build the reported record for one candidate."""

    return {
        "platform": candidate.platform,
        "status": "NOT_FOUND" if verification == NOT_FOUND else "FOUND",
        "profile_url": candidate.url,
        "final_url": (outcome.final_url if outcome else candidate.url) or candidate.url,
        "verification": verification,
        "verification_note": note,
        "http_status": outcome.status if outcome else None,
        "checked": bool(checked),
        "checked_at": utc_now_iso(),
    }


async def verify_candidates(
    candidates: Sequence[Candidate],
    username: str,
    fetcher: Optional[Fetcher] = None,
    *,
    budget: float = VERIFY_BUDGET_SECONDS,
    request_timeout: float = VERIFY_REQUEST_TIMEOUT,
    max_candidates: int = MAX_VERIFY_CANDIDATES,
    concurrency: int = VERIFY_CONCURRENCY,
) -> List[Dict[str, object]]:
    """Verify up to ``max_candidates`` candidates and return their records.

    Candidates beyond the cap, and any left when the budget runs out, are
    reported as inconclusive rather than being quietly dropped. ``fetcher`` is
    injectable so tests never touch the network.
    """

    ordered = list(candidates)
    selected = ordered[:max(0, max_candidates)]
    skipped = ordered[max(0, max_candidates):]

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, float(budget))
    semaphore = asyncio.Semaphore(max(1, int(concurrency)))

    client = None
    if fetcher is None:
        client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=max(0.5, float(request_timeout)),
            headers={"User-Agent": USER_AGENT,
                     "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"},
        )

        async def _pooled_fetch(url: str, timeout: float) -> FetchOutcome:
            """Reuse one connection pool for the whole verification pass."""
            return await default_fetcher(url, timeout, client=client)

        fetcher = _pooled_fetch

    async def check_one(index: int, candidate: Candidate):
        async with semaphore:
            remaining = deadline - loop.time()
            if remaining <= 0.1:
                return index, candidate_result(
                    candidate, INCONCLUSIVE,
                    "Not checked: the verification time budget ran out.")
            wait = max(0.5, min(float(request_timeout), remaining))
            try:
                outcome = await asyncio.wait_for(
                    fetcher(candidate.url, wait), timeout=wait + 1.0)
            except asyncio.TimeoutError:
                outcome = FetchOutcome(final_url=candidate.url, failure="timeout",
                                       note=_failure_note("timeout"))
            except Exception as error:  # a broken fetcher must not lose evidence
                outcome = FetchOutcome(
                    final_url=candidate.url, failure="error",
                    note=f"Not fetched: {type(error).__name__}.")
            verification, note = classify(outcome, candidate.url, username)
            return index, candidate_result(candidate, verification, note,
                                           outcome, checked=True)

    try:
        outcomes = await asyncio.gather(
            *(check_one(index, candidate) for index, candidate in enumerate(selected))
        )
    finally:
        if client is not None:
            await client.aclose()

    records = [record for _, record in sorted(outcomes, key=lambda pair: pair[0])]
    for candidate in skipped:
        records.append(candidate_result(
            candidate, INCONCLUSIVE,
            "Not checked: the per-scan limit on verified candidates was reached."))
    return records


# -------------------------------------------------------------- public API --


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _safe_error(error: Exception) -> str:
    """A short, non-sensitive description of a failure."""

    text = _WHITESPACE_RE.sub(" ", str(error)).strip()
    return f"{type(error).__name__}: {text[:300]}" if text else type(error).__name__


def summarize(entries: Sequence[Dict[str, object]], verify: bool,
              started_at: str) -> Dict[str, object]:
    """Turn per-candidate records into the reported result."""

    visible = [e for e in entries if e.get("verification") != NOT_FOUND]
    confirmed = sum(1 for e in entries if e.get("verification") == CONFIRMED)
    inconclusive = sum(1 for e in entries if e.get("verification") == INCONCLUSIVE)
    absent = sum(1 for e in entries if e.get("verification") == NOT_FOUND)
    checked = sum(1 for e in entries if e.get("checked"))

    if not verify:
        status = "FOUND" if visible else "NOT_FOUND"
        message = (
            f"Found {len(visible)} profile candidate(s). Page verification was "
            "turned off, so none of them were confirmed."
        ) if visible else "No profile candidates found."
    elif confirmed:
        status = "FOUND"
        message = f"Confirmed {confirmed} profile(s)."
        if inconclusive:
            message += f" {inconclusive} further candidate(s) could not be verified."
    elif inconclusive:
        status = "UNKNOWN"
        message = (
            f"{inconclusive} profile candidate(s) were found but none could be "
            "confirmed by the platform pages themselves."
        )
    else:
        status = "NOT_FOUND"
        message = "No profiles found."
        if absent:
            message = (
                f"No profiles found: {absent} candidate(s) were checked and "
                "each page said the account does not exist."
            )

    return {
        "status": status,
        "message": message,
        "results": visible,
        "candidates_count": len(entries),
        "checked_count": checked,
        "confirmed_count": confirmed,
        "inconclusive_count": inconclusive,
        "not_found_count": absent,
        "verification_enabled": bool(verify),
        "started_at": started_at,
        "finished_at": utc_now_iso(),
    }


async def check_username(username: str, timeout: float = None,
                         verify: bool = True,
                         fetcher: Optional[Fetcher] = None) -> Dict[str, object]:
    """Look up one handle across public platforms.

    Args:
        username: handle to look up.
        timeout: overall budget in seconds for the Sherlock search. None uses
            SHERLOCK_TIMEOUT_SECONDS. The verification pass gets its own,
            smaller budget (``VERIFY_BUDGET_SECONDS``).
        verify: when False, Sherlock's hits are reported as unverified
            candidates and no page is ever fetched.
        fetcher: injectable page fetcher, used by tests.

    Returns:
        A dict with ``status`` in FOUND / NOT_FOUND / UNKNOWN / ERROR, the
        per-candidate ``results`` (each carrying its verification, HTTP status,
        final URL and check time), and honest counters for what was and was not
        verified.
    """

    raw = (username or "").strip()
    started_at = utc_now_iso()

    reason = validate_username(raw)
    if reason:
        return {
            "username": raw, "status": "ERROR", "message": reason,
            "results": [], "started_at": started_at, "finished_at": utc_now_iso(),
        }

    try:
        completed = await asyncio.to_thread(run_sherlock, raw, timeout)
    except subprocess.TimeoutExpired:
        return {
            "username": raw, "status": "UNKNOWN",
            "message": "Sherlock search timed out.",
            "results": [], "started_at": started_at, "finished_at": utc_now_iso(),
        }
    except ValueError as error:
        return {
            "username": raw, "status": "ERROR", "message": str(error),
            "results": [], "started_at": started_at, "finished_at": utc_now_iso(),
        }
    except Exception as error:
        return {
            "username": raw, "status": "ERROR", "message": _safe_error(error),
            "results": [], "started_at": started_at, "finished_at": utc_now_iso(),
        }

    if completed.returncode != 0:
        message = _WHITESPACE_RE.sub(" ", (completed.stderr or "")).strip()
        return {
            "username": raw, "status": "ERROR",
            "message": message[:500] or "Sherlock search failed.",
            "results": [], "started_at": started_at, "finished_at": utc_now_iso(),
        }

    candidates = parse_candidates(completed.stdout)

    if verify:
        entries = await verify_candidates(candidates, raw, fetcher)
    else:
        entries = [candidate_result(
            candidate, INCONCLUSIVE,
            "Not checked: page verification was turned off for this lookup.")
            for candidate in candidates]

    summary = summarize(entries, verify, started_at)
    return {"username": raw, **summary}

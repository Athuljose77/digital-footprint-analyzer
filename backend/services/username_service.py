import asyncio
import subprocess
import sys
import re
from urllib.parse import urlparse


TIMEOUT_SECONDS = 90


def run_sherlock(username: str):
    """
    Run Sherlock using the same Python interpreter
    that is running the backend.
    """

    command = [
        sys.executable,
        "-m",
        "sherlock_project",
        username,
        "--print-found",
        "--no-color",
        "--timeout",
        "10",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT_SECONDS,
    )

    return result


async def check_username(username: str) -> dict:
    """
    Search for a username across public platforms
    using Sherlock.
    """

    username = username.strip()

    # -------------------------
    # Input validation
    # -------------------------

    if not username:
        return {
            "username": username,
            "status": "ERROR",
            "message": "Username cannot be empty.",
            "results": []
        }

    if len(username) > 100:
        return {
            "username": username,
            "status": "ERROR",
            "message": "Username is too long.",
            "results": []
        }

    # -------------------------
    # Run Sherlock
    # -------------------------

    try:
        result = await asyncio.to_thread(
            run_sherlock,
            username
        )

    except subprocess.TimeoutExpired:
        return {
            "username": username,
            "status": "UNKNOWN",
            "message": "Sherlock search timed out.",
            "results": []
        }

    except Exception as error:
        return {
            "username": username,
            "status": "ERROR",
            "message": (
                f"{type(error).__name__}: "
                f"{str(error)}"
            ),
            "results": []
        }

    output = result.stdout
    error_output = result.stderr

    # -------------------------
    # Sherlock execution error
    # -------------------------

    if result.returncode != 0:
        return {
            "username": username,
            "status": "ERROR",
            "message": (
                error_output.strip()
                or "Sherlock search failed."
            ),
            "results": []
        }

    # -------------------------
    # Parse Sherlock output
    # -------------------------

    results = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        # Only process lines containing URLs
        if (
            "http://" not in line
            and "https://" not in line
        ):
            continue

        # Ignore Sherlock informational/footer links
        if line.startswith("Try OSINTSearch"):
            continue

        # Extract URL
        url_match = re.search(
            r"https?://\S+",
            line
        )

        if not url_match:
            continue

        profile_url = url_match.group(0)

        # Remove punctuation accidentally captured
        profile_url = profile_url.rstrip(
            ".,)]}>"
        )

        # Parse URL
        parsed = urlparse(profile_url)

        # --------------------------------
        # Ignore platform homepages
        # --------------------------------

        if (
            parsed.path in ("", "/")
            and not parsed.query
        ):
            continue

        # --------------------------------
        # Ignore known API/search endpoints
        # --------------------------------

        ignored_url_parts = [
            "/api/",
            "/search",
            "/query",
            "/lookup",
            "/osint-tools/",
            "api.mojang.com",
        ]

        url_to_check = (
            parsed.netloc
            + parsed.path
            + "?"
            + parsed.query
        ).lower()

        if any(
            part in url_to_check
            for part in ignored_url_parts
        ):
            continue

        # --------------------------------
        # Ignore search/query parameters
        # --------------------------------

        query_lower = parsed.query.lower()

        if (
            "search/" in query_lower
            or "search=" in query_lower
            or "query=" in query_lower
        ):
            continue

        # --------------------------------
        # Ignore Wikipedia account-management pages
        # --------------------------------

        if (
            parsed.netloc.lower() == "en.wikipedia.org"
            and parsed.path.lower().startswith(
                "/wiki/special:centralauth/"
            )
        ):
            continue

        # --------------------------------
        # Extract platform name
        # --------------------------------

        platform = extract_platform(
            line,
            profile_url
        )

        results.append(
            {
                "platform": platform,
                "status": "FOUND",
                "profile_url": profile_url
            }
        )

    # -------------------------
    # Remove duplicate URLs
    # -------------------------

    unique_results = []

    seen_urls = set()

    for result_item in results:

        url = result_item["profile_url"]

        if url in seen_urls:
            continue

        seen_urls.add(url)

        unique_results.append(
            result_item
        )

    results = unique_results

    # -------------------------
    # Final result
    # -------------------------

    if results:
        return {
            "username": username,
            "status": "FOUND",
            "results": results
        }

    return {
        "username": username,
        "status": "NOT_FOUND",
        "results": []
    }


def extract_platform(
    line: str,
    profile_url: str
) -> str:
    """
    Extract the platform name from Sherlock output.
    """

    # Sherlock output usually contains:
    # [+] Platform: URL

    if ":" in line:

        prefix = line.split(
            ":",
            1
        )[0].strip()

        prefix = prefix.lstrip(
            "[+]"
        ).strip()

        if prefix:
            return prefix

    # Fallback to hostname
    try:

        parsed = urlparse(
            profile_url
        )

        hostname = parsed.hostname

        if hostname:
            return hostname

    except Exception:
        pass

    return "Unknown"
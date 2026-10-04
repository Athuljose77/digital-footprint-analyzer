import asyncio
import subprocess
import sys
import re
from urllib.parse import urlparse


TIMEOUT_SECONDS = 120


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

    # -----------------------------------------
    # CLEAN USERNAME
    # -----------------------------------------

    username = username.strip()

    # -----------------------------------------
    # VALIDATION
    # -----------------------------------------

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

    # -----------------------------------------
    # RUN SHERLOCK
    # -----------------------------------------

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

    # -----------------------------------------
    # GET OUTPUT
    # -----------------------------------------

    output = result.stdout

    error_output = result.stderr

    # -----------------------------------------
    # SHERLOCK PROCESS ERROR
    # -----------------------------------------

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

    # -----------------------------------------
    # PARSE RESULTS
    # -----------------------------------------

    results = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        # Sherlock found results normally
        # contain a URL.
        if (
            "http://" not in line
            and "https://" not in line
        ):
            continue

        # -------------------------------------
        # EXTRACT URL
        # -------------------------------------

        url_match = re.search(
            r"https?://\S+",
            line
        )

        if not url_match:
            continue

        profile_url = url_match.group(0)

        profile_url = profile_url.rstrip(
            ".,)]}>"
        )

        # -------------------------------------
        # EXTRACT PLATFORM
        # -------------------------------------

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

    # -----------------------------------------
    # REMOVE DUPLICATES
    # -----------------------------------------

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

    # -----------------------------------------
    # FINAL RESULT
    # -----------------------------------------

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

    # -----------------------------------------
    # SHERLOCK FORMAT
    # -----------------------------------------

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

    # -----------------------------------------
    # URL FALLBACK
    # -----------------------------------------

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
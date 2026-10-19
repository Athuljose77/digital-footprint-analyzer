import re

from services.email_service import check_email
from services.username_service import check_username



# -----------------------------
# EMAIL VALIDATION
# -----------------------------

def validate_email(email: str) -> bool:

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(
        re.match(
            pattern,
            email.strip()
        )
    )


# -----------------------------
# USERNAME ANALYSIS
# -----------------------------

async def analyze_username(
    username: str
) -> dict:

    username = username.strip()

    result = await check_username(username)

    if result.get("status") == "ERROR":

        return {
            "type": "username",
            "input": username,
            "status": "ERROR",
            "message": result.get(
                "message",
                "Username analysis failed."
            ),
            "results": []
        }

    results = result.get(
        "results",
        []
    )

    found = len(results)

    # Verification counters. A candidate that could not be confirmed is
    # reported, but is never mixed into the confirmed total.
    confirmed = int(result.get("confirmed_count", 0) or 0)
    inconclusive = int(result.get("inconclusive_count", 0) or 0)
    checked = int(result.get("checked_count", 0) or 0)
    verification_enabled = bool(result.get("verification_enabled", False))

    # -------------------------
    # Username exposure score
    # -------------------------

    # Only profiles that were actually confirmed move the score when
    # verification ran; otherwise the score falls back to the candidate count,
    # and score_basis says which of the two was used.
    if verification_enabled:
        scored = confirmed
        score_basis = (
            f"Based on {confirmed} confirmed profile(s); "
            f"{inconclusive} unverified candidate(s) were not counted."
        )
    else:
        scored = found
        score_basis = (
            f"Based on {found} candidate(s) reported by the discovery tool; "
            "page verification was turned off, so none were confirmed."
        )

    if scored == 0:

        exposure_score = 0

    elif scored <= 2:

        exposure_score = 20

    elif scored <= 5:

        exposure_score = 40

    elif scored <= 10:

        exposure_score = 60

    elif scored <= 20:

        exposure_score = 80

    else:

        exposure_score = 100

    return {
        "type": "username",
        "input": username,
        "status": result.get("status"),
        "message": result.get("message", ""),
        "profiles_found": found,
        "confirmed_count": confirmed,
        "inconclusive_count": inconclusive,
        # Kept for existing consumers: candidates that remain unverified.
        "unknown_count": inconclusive,
        # Platforms actually checked by the verification layer. This used to be
        # the number of profiles found, which made the label say something the
        # data did not.
        "platform_count": checked,
        "candidates_count": int(result.get("candidates_count", found) or 0),
        "not_found_count": int(result.get("not_found_count", 0) or 0),
        "verification_enabled": verification_enabled,
        "score_basis": score_basis,
        "checked_at": result.get("finished_at", ""),
        "exposure_score": exposure_score,
        "results": results
    }


# -----------------------------
# EMAIL ANALYSIS
# -----------------------------

async def analyze_email(
    email: str
) -> dict:

    email = email.strip().lower()

    # Validate email
    if not validate_email(email):

        return {
            "type": "email",
            "input": email,
            "status": "ERROR",
            "message": "Invalid email address."
        }

    # Check email
    result = await check_email(
        email
    )

    # Real-time checker unavailable
    if result.get("status") == "UNAVAILABLE":

        return {
            "type": "email",
            "input": email,
            "status": "UNAVAILABLE",
            "exposure_score": None,
            "breach_count": None,
            "breaches": [],
            "exposed_sites": [],
            "message": result.get(
                "message",
                "Real-time email breach checking is unavailable."
            )
        }

    # API/checker error
    if result.get("status") == "ERROR":

        return {
            "type": "email",
            "input": email,
            "status": "ERROR",
            "message": result.get(
                "message",
                "Email check failed."
            )
        }

    breaches = result.get(
        "breaches",
        []
    )

    # -------------------------
    # Extract exposed sites
    # -------------------------

    exposed_sites = []

    for breach in breaches:

        site_name = breach.get(
            "name",
            "Unknown"
        )

        exposed_sites.append(
            {
                "site": site_name,
                "breach_date": breach.get(
                    "breach_date",
                    "Unknown"
                ),
                "industry": breach.get(
                    "industry",
                    "Unknown"
                ),
                "verified": breach.get(
                    "verified",
                    False
                )
            }
        )

    # Remove duplicate sites
    unique_sites = []

    seen_sites = set()

    for site in exposed_sites:

        site_name = site["site"]

        if site_name not in seen_sites:

            seen_sites.add(
                site_name
            )

            unique_sites.append(
                site
            )

    # Project-specific score
    exposure_score = min(
        len(breaches) * 15,
        100
    )

    return {
        "type": "email",
        "input": email,
        "status": "ANALYZED",
        "exposure_score": exposure_score,
        "breach_count": len(breaches),
        "breaches": breaches,
        "exposed_sites": unique_sites
    }


# -----------------------------
# MAIN ANALYZER
# -----------------------------

async def analyze(
    identifier_type: str,
    value: str
) -> dict:

    # Empty input
    if not value or not value.strip():

        return {
            "status": "ERROR",
            "message": (
                "Please enter a username or email."
            )
        }

    # Username
    if identifier_type == "username":

        return await analyze_username(
            value
        )

    # Email
    if identifier_type == "email":

        return await analyze_email(
            value
        )

    # Invalid type
    return {
        "status": "ERROR",
        "message": (
            "Type must be 'username' or 'email'."
        )
    }
import httpx
import re

from urllib.parse import quote

from services.email_service import check_email
from services.username_service import check_username


# Platforms to check for username
PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Hugging Face": "https://huggingface.co/{}",
    "Dev.to": "https://dev.to/{}",
    "Medium": "https://medium.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "CodePen": "https://codepen.io/{}",
    "Replit": "https://replit.com/@{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "npm": "https://www.npmjs.com/~{}",
    "PyPI": "https://pypi.org/user/{}/",
    "Keybase": "https://keybase.io/{}",
    "Buy Me a Coffee": "https://www.buymeacoffee.com/{}",
}


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
# CHECK USERNAME PLATFORM
# -----------------------------

async def check_platform(
    client: httpx.AsyncClient,
    platform: str,
    url_template: str,
    username: str
) -> dict:

    encoded_username = quote(
        username,
        safe=""
    )

    profile_url = url_template.format(
        encoded_username
    )

    try:

        response = await client.get(
            profile_url
        )

        if response.status_code == 200:

            status = "FOUND"

        elif response.status_code == 404:

            status = "NOT_FOUND"

        elif response.status_code in [
            401,
            403,
            429
        ]:

            status = "UNKNOWN"

        else:

            status = "UNKNOWN"

    except httpx.RequestError:

        status = "UNKNOWN"

    return {
        "platform": platform,
        "status": status,
        "profile_url": profile_url
    }


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

    # -------------------------
    # Username exposure score
    # -------------------------

    if found == 0:

        exposure_score = 0

    elif found <= 2:

        exposure_score = 20

    elif found <= 5:

        exposure_score = 40

    elif found <= 10:

        exposure_score = 60

    elif found <= 20:

        exposure_score = 80

    else:

        exposure_score = 100

    return {
        "type": "username",
        "input": username,
        "status": result.get("status"),
        "profiles_found": found,
        "platform_count": found,
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
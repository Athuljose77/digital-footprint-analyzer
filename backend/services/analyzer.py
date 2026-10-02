import re
from urllib.parse import quote
from services.email_service import check_email

import httpx


PLATFORMS = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Hugging Face": "https://huggingface.co/{}",
    "Dev.to": "https://dev.to/{}",
}


def validate_email(email: str) -> bool:
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email.strip()))


async def analyze_username(username: str) -> dict:
    username = username.strip()

    results = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=8.0,
        headers={
            "User-Agent": "DigitalFootprintAnalyzer/1.0"
        }
    ) as client:

        for platform, url_template in PLATFORMS.items():

            profile_url = url_template.format(
                quote(username)
            )

            try:
                response = await client.get(profile_url)

                if response.status_code == 200:
                    status = "FOUND"

                elif response.status_code == 404:
                    status = "NOT_FOUND"

                else:
                    status = "UNKNOWN"

            except httpx.RequestError:
                status = "UNKNOWN"

            results.append({
                "platform": platform,
                "status": status,
                "profile_url": profile_url
            })

    found = sum(
        1 for item in results
        if item["status"] == "FOUND"
    )

    exposure_score = min(found * 15, 100)

    return {
        "type": "username",
        "input": username,
        "profiles_found": found,
        "exposure_score": exposure_score,
        "results": results
    }


async def analyze_email(email: str) -> dict:
    email = email.strip().lower()

    if not validate_email(email):
        return {
            "type": "email",
            "input": email,
            "status": "ERROR",
            "message": "Invalid email address."
        }

    result = await check_email(email)

    if result.get("status") == "error":
        return {
            "type": "email",
            "input": email,
            "status": "ERROR",
            "message": result.get("message", "Email check failed.")
        }

    return {
        "type": "email",
        "input": email,
        "status": "ANALYZED",
        "breach_count": result.get("breach_count", 0),
        "breaches": result.get("breaches", [])
    }


async def analyze(identifier_type: str, value: str) -> dict:

    if not value or not value.strip():
        return {
            "status": "ERROR",
            "message": "Please enter a username or email."
        }

    if identifier_type == "username":
        return await analyze_username(value)

    if identifier_type == "email":
        return await analyze_email(value)

    return {
        "status": "ERROR",
        "message": "Type must be 'username' or 'email'."
    }

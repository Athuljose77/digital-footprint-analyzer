import re
import httpx


def validate_email(email: str) -> bool:
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email.strip()))


def process_breach_details(data: dict) -> list:
    breaches = []

    for breach in data.get("breach_details", []):
        breaches.append({
            "name": breach.get("name"),
            "records_exposed": breach.get("records_exposed"),
            "breach_date": breach.get("breach_date"),
            "industry": breach.get("company", {}).get("industry"),
            "password_risk": breach.get("security", {}).get("password_risk"),
            "verified": breach.get("security", {}).get("is_verified"),
            "exposed_data": breach.get("exposed_data", [])
        })

    return breaches


async def check_email(email: str):

    email = email.strip().lower()

    if not validate_email(email):
        return {
            "status": "error",
            "message": "Invalid email address."
        }

    url = f"https://api.xposedornot.com/v1/check-email/{email}?details=true"

    async with httpx.AsyncClient() as client:
        response = await client.get(url)

    data = response.json()

    breaches = process_breach_details(data)

    return {
        "status": "success",
        "email": email,
        "breach_count": len(breaches),
        "breaches": breaches
    }
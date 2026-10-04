import httpx
from urllib.parse import quote


async def check_email(email: str) -> dict:
    """
    Check an email address against XposedOrNot
    and return detailed breach information.
    """

    encoded_email = quote(
        email.strip(),
        safe=""
    )

    url = (
        f"https://api.xposedornot.com/v1/check-email/"
        f"{encoded_email}?details=true"
    )

    try:

        async with httpx.AsyncClient(
            timeout=15.0
        ) as client:

            response = await client.get(url)

        data = response.json()

        # -----------------------------
        # EMAIL NOT FOUND
        # -----------------------------

        if data.get("Error") == "Not found":

            return {
                "status": "SUCCESS",
                "breaches": []
            }

        # -----------------------------
        # EMAIL FOUND
        # -----------------------------

        if data.get("status") == "success":

            raw_breaches = data.get(
                "breach_details",
                []
            )

            breaches = []

            for breach in raw_breaches:

                breaches.append({
                    "name": breach.get(
                        "name"
                    ),

                    "records_exposed": breach.get(
                        "records_exposed"
                    ),

                    "breach_date": breach.get(
                        "breach_date"
                    ),

                    "industry": breach.get(
                        "company",
                        {}
                    ).get(
                        "industry"
                    ),

                    "password_risk": breach.get(
                        "security",
                        {}
                    ).get(
                        "password_risk"
                    ),

                    "verified": breach.get(
                        "security",
                        {}
                    ).get(
                        "is_verified"
                    ),

                    "exposed_data": breach.get(
                        "exposed_data",
                        []
                    )
                })

            return {
                "status": "SUCCESS",
                "breaches": breaches
            }

        # -----------------------------
        # RATE LIMIT
        # -----------------------------

        if response.status_code == 429:

            return {
                "status": "ERROR",
                "message": (
                    "Too many requests. "
                    "Please wait and try again."
                )
            }

        # -----------------------------
        # UNEXPECTED RESPONSE
        # -----------------------------

        return {
            "status": "ERROR",
            "message": (
                "Unexpected response from "
                "XposedOrNot."
            )
        }

    except httpx.RequestError:

        return {
            "status": "ERROR",
            "message": (
                "Could not connect to the "
                "breach database."
            )
        }

    except ValueError:

        return {
            "status": "ERROR",
            "message": (
                "Invalid response from the "
                "breach database."
            )
        }
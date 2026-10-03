import httpx
from urllib.parse import quote


async def check_email(email: str) -> dict:
    """
    Check an email address against XposedOrNot.
    """

    encoded_email = quote(email, safe="")

    url = (
        f"https://api.xposedornot.com/v1/check-email/"
        f"{encoded_email}"
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
                "breaches",
                []
            )

            # XposedOrNot returns:
            #
            # "breaches": [
            #     ["Site1", "Site2", "Site3"]
            # ]
            #
            # Convert it into:
            #
            # ["Site1", "Site2", "Site3"]

            breaches = []

            if raw_breaches:

                for item in raw_breaches:

                    if isinstance(item, list):

                        breaches.extend(item)

                    elif isinstance(item, str):

                        breaches.append(item)

            return {
                "status": "SUCCESS",
                "breaches": [
                    {
                        "name": name
                    }
                    for name in breaches
                ]
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

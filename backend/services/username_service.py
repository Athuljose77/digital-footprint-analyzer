def validate_username(username: str) -> bool:
    if not username:
        return False

    username = username.strip()

    if not username:
        return False

    if len(username) > 100:
        return False

    return True


def create_result(
    platform: str,
    status: str,
    profile_url: str | None = None
) -> dict:
    return {
        "platform": platform,
        "status": status,
        "profile_url": profile_url
    }


async def search_username(username: str) -> dict:
    if not validate_username(username):
        return {
            "username": username,
            "status": "ERROR",
            "results": []
        }

    return {
        "username": username.strip(),
        "status": "UNKNOWN",
        "results": []
    }

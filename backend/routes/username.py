from fastapi import APIRouter

from services.username_service import check_username


router = APIRouter(
    prefix="/username",
    tags=["Username"]
)


@router.get("/{username}")
async def username_search(username: str):

    result = await check_username(username)

    return result
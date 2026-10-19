"""Username lookup endpoint.

The path segment is validated by the same rules the service enforces, so an
invalid handle is rejected before a subprocess is ever started, and the whole
lookup runs inside the shared concurrency and time limits.
"""

from fastapi import APIRouter, Path
from fastapi.responses import JSONResponse

from services.limits import AnalysisTimeout, ServerBusy, limited_analysis
from services.username_service import check_username


router = APIRouter(
    prefix="/username",
    tags=["Username"]
)


USERNAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


@router.get("/{username}")
async def username_search(
    username: str = Path(
        ...,
        min_length=1,
        max_length=64,
        pattern=USERNAME_PATTERN,
        description="Handle to look up. Letters, digits, '.', '_' and '-' only.",
    ),
):
    try:
        async with limited_analysis():
            return await check_username(username)
    except ServerBusy as error:
        return JSONResponse(
            status_code=429,
            content={"status": "ERROR", "message": str(error)},
        )
    except AnalysisTimeout as error:
        return JSONResponse(
            status_code=504,
            content={"status": "ERROR", "message": str(error)},
        )

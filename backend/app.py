"""Digital Footprint Analyzer API.

Thin HTTP wrapper around the same services the desktop app uses. Input is
validated before anything is run: the API starts subprocesses and makes
outbound requests, so an unvalidated field would be a denial-of-service and
argument-injection surface.

Every error is reported honestly: a rejected request says what was wrong, a
busy server says it is busy, and a failure is never dressed up as a result.
"""

from typing import Literal

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from routes.username import router as username_router
from services.analyzer import analyze
from services.limits import AnalysisTimeout, ServerBusy, limited_analysis


app = FastAPI(
    title="Digital Footprint Analyzer"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


MAX_VALUE_LENGTH = 254  # longest valid email address


class AnalyzeRequest(BaseModel):
    """One analysis request, constrained before it reaches a service."""

    type: Literal["username", "email"]
    value: str = Field(..., min_length=1, max_length=MAX_VALUE_LENGTH)


def validation_message(error: RequestValidationError) -> str:
    """Turn a validation failure into one plain sentence."""

    for detail in error.errors():
        location = ".".join(str(part) for part in detail.get("loc", ()))
        if location.endswith("type"):
            return "Type must be 'username' or 'email'."
        if location.endswith("value"):
            if detail.get("type") == "string_too_long":
                return f"That value is too long (limit {MAX_VALUE_LENGTH} characters)."
            return "Please enter a username or email address."
    return "That request could not be understood."


@app.exception_handler(RequestValidationError)
async def on_validation_error(_request, error: RequestValidationError):
    """Return the same JSON shape as every other error, so clients can show it."""

    return JSONResponse(
        status_code=400,
        content={"status": "ERROR", "message": validation_message(error)},
    )


@app.get("/")
def root():
    return {
        "message": "Digital Footprint Analyzer API is running"
    }


@app.post("/analyze")
async def run_analysis(request: AnalyzeRequest):
    try:
        async with limited_analysis():
            return await analyze(request.type, request.value)
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


app.include_router(username_router)

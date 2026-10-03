from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.analyzer import analyze


app = FastAPI(title="Digital Footprint Analyzer")


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


class AnalyzeRequest(BaseModel):
    type: str
    value: str


@app.get("/")
def root():
    return {
        "message": "Digital Footprint Analyzer API is running"
    }


@app.post("/analyze")
async def run_analysis(request: AnalyzeRequest):
    return await analyze(request.type, request.value)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.username import router as username_router


app = FastAPI(
    title="Digital Footprint Analyzer"
)


# -----------------------------------------
# CORS CONFIGURATION
# -----------------------------------------

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


# -----------------------------------------
# ROOT ROUTE
# -----------------------------------------

@app.get("/")
def root():
    return {
        "message": (
            "Digital Footprint Analyzer "
            "API is running"
        )
    }


# -----------------------------------------
# USERNAME ROUTES
# -----------------------------------------

app.include_router(
    username_router
)
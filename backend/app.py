from fastapi import FastAPI

app = FastAPI(title="Digital Footprint Analyzer")


@app.get("/")
def root():
    return {"message": "Digital Footprint Analyzer API is running"}

from fastapi import FastAPI

app = FastAPI(
    title="Електронний деканат",
    description="Захищений REST API для навчального закладу",
    version="1.0.0"
)

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}

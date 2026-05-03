"""FastAPI application factory for the API Security Scanner."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from api.routes import router

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def create_app() -> FastAPI:
    app = FastAPI(
        title="API Security Scanner",
        description="OWASP API Top-10 + GraphQL + fuzzing scanner",
        version="1.0.0",
    )

    app.include_router(router)

    @app.get("/", response_class=HTMLResponse)
    def index():
        html = (_TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(content=html)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

"""PCI DSS v4.0 Scope Reduction - FastAPI 入口（端口 5032）"""
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .api import router

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="PCI DSS v4.0 Scope Reduction & Audit Engine",
    description="Project CardShield — 12 PCI req + CDE 网络隔离 + PanHunter + AES-256-GCM Tokenization",
    version="1.0.0",
)


@app.on_event("startup")
def _startup():
    from .models import seed_all
    seed_all(verbose=False)


app.include_router(router, prefix="/api")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "PCI DSS Scope Reduction Engine", "docs": "/docs"}


def run():
    import uvicorn
    import os
    port = int(os.environ.get("WEB_PORT", "5032"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
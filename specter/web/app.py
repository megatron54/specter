"""Specter Web Dashboard.

FastAPI application providing a web UI for device discovery and control.
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path

app = FastAPI(title="Specter", version="0.1.0")

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/devices")
async def list_devices():
    """Return all discovered devices. TODO: integrate with scanner."""
    return {"devices": []}


@app.post("/api/scan")
async def trigger_scan():
    """Trigger a network scan. TODO: implement."""
    return {"status": "scanning"}

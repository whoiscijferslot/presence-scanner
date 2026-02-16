"""FastAPI application for presence scanner."""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from .config import (
    DEVICES,
    HUE_BRIDGE_IP,
    HUE_TOKENS_FILE,
    LIVING_ROOM_GROUP,
    SCAN_INTERVAL,
    VALOU_ROOM_GROUP,
)
from .database import (
    get_all_device_states,
    get_valou_status_history,
    init_db,
    save_valou_status_history,
)
from .scanner import run_scan

# Debounce for manual scan trigger
TRIGGER_DEBOUNCE = 5
last_trigger_time = 0.0

# Background scanner task
scanner_task: asyncio.Task | None = None


async def background_scanner():
    """Background task that runs scans periodically."""
    while True:
        try:
            await run_scan()
        except Exception as e:
            logger.error(f"Scan failed: {e}")
        await asyncio.sleep(SCAN_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    global scanner_task
    
    # Initialize database
    init_db()
    logger.info("Database initialized")
    
    # Start background scanner
    scanner_task = asyncio.create_task(background_scanner())
    logger.info(f"Background scanner started (interval: {SCAN_INTERVAL}s)")
    
    yield
    
    # Shutdown
    if scanner_task:
        scanner_task.cancel()
        try:
            await scanner_task
        except asyncio.CancelledError:
            pass
    logger.info("Scanner stopped")


app = FastAPI(
    title="Presence Scanner",
    version="2.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------
# Hue integration helpers
# --------------------------------------------------------------------------

def load_hue_username() -> str | None:
    """Load Hue API username from bedwolf config."""
    try:
        with HUE_TOKENS_FILE.open() as f:
            data = json.load(f)
            return data.get("username")
    except (FileNotFoundError, json.JSONDecodeError):
        return None


async def get_room_state(client: httpx.AsyncClient, username: str, group_id: str) -> bool:
    """Check if any light in a room is on."""
    try:
        response = await client.get(
            f"http://{HUE_BRIDGE_IP}/api/{username}/groups/{group_id}",
            timeout=5.0
        )
        data = response.json()
        return data.get("state", {}).get("any_on", False)
    except Exception:
        return False


ValouStatus = Literal["downstairs", "around", "awake", "sleeping", "away"]


def determine_valou_status(
    present: bool,
    minutes_away: float,
    living_room_on: bool,
    valou_room_on: bool
) -> tuple[ValouStatus, str]:
    """Determine Roomie's status based on presence and room lights."""
    is_effectively_home = present or minutes_away < 5

    if not is_effectively_home:
        return "away", "Away"
    elif living_room_on and not valou_room_on:
        return "downstairs", "Downstairs"
    elif living_room_on and valou_room_on:
        return "around", "Around"
    elif not living_room_on and valou_room_on:
        return "awake", "Awake"
    else:
        return "sleeping", "Sleeping"


# --------------------------------------------------------------------------
# API Endpoints
# --------------------------------------------------------------------------

@app.post("/api/scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """Trigger a manual presence scan."""
    global last_trigger_time
    now = time.time()
    elapsed = now - last_trigger_time

    if elapsed < TRIGGER_DEBOUNCE:
        return JSONResponse({
            "status": "debounced",
            "retry_after": TRIGGER_DEBOUNCE - elapsed
        }, status_code=429)

    last_trigger_time = now
    background_tasks.add_task(run_scan)
    return {"status": "triggered"}


@app.get("/api/roomie-status")
async def valou_status():
    """Get enhanced Roomie status based on presence + room lights."""
    presence_data = get_all_device_states()
    
    if not presence_data.get("devices"):
        return JSONResponse({"error": "No presence data"}, status_code=500)

    roomie = presence_data["devices"].get("roomie", {})
    present = roomie.get("present", False)
    last_online = roomie.get("last_online")
    
    # Calculate minutes away
    minutes_away = float("inf")
    if last_online:
        try:
            last_online_dt = datetime.fromisoformat(last_online.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            minutes_away = (now - last_online_dt).total_seconds() / 60
        except Exception:
            pass

    # Get Hue room states
    hue_username = load_hue_username()
    living_room_on = False
    valou_room_on = False

    if hue_username:
        async with httpx.AsyncClient() as client:
            living_room_on, valou_room_on = await asyncio.gather(
                get_room_state(client, hue_username, LIVING_ROOM_GROUP),
                get_room_state(client, hue_username, VALOU_ROOM_GROUP),
            )

    # Determine status
    now = datetime.now(timezone.utc)
    status, label = determine_valou_status(present, minutes_away, living_room_on, valou_room_on)

    # Track status changes
    history = get_valou_status_history()
    
    if history.get("status") != status:
        since_iso = now.isoformat().replace("+00:00", "Z")
        save_valou_status_history(status, since_iso)
        since = since_iso
    else:
        since = history.get("since")
    
    # Calculate duration
    since_minutes = None
    since_human = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            since_minutes = (now - since_dt).total_seconds() / 60
            since_human = since_dt.strftime("%H:%M")
        except Exception:
            pass

    return {
        "status": status,
        "label": label,
        "present": present,
        "last_online": last_online,
        "minutes_away": minutes_away if minutes_away != float("inf") else None,
        "living_room_on": living_room_on,
        "valou_room_on": valou_room_on,
        "since": since,
        "since_minutes": round(since_minutes) if since_minutes is not None else None,
        "since_human": since_human,
    }


@app.get("/api/status")
async def full_status():
    """Get full presence status for all devices + enhanced Roomie status."""
    presence_data = get_all_device_states()
    
    if not presence_data.get("devices"):
        return JSONResponse({"error": "No presence data"}, status_code=500)

    roomie = presence_data["devices"].get("roomie", {})
    present = roomie.get("present", False)
    last_online = roomie.get("last_online")
    
    # Calculate minutes away
    minutes_away = float("inf")
    if last_online:
        try:
            last_online_dt = datetime.fromisoformat(last_online.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            minutes_away = (now - last_online_dt).total_seconds() / 60
        except Exception:
            pass

    # Get Hue room states
    hue_username = load_hue_username()
    living_room_on = False
    valou_room_on = False

    if hue_username:
        async with httpx.AsyncClient() as client:
            living_room_on, valou_room_on = await asyncio.gather(
                get_room_state(client, hue_username, LIVING_ROOM_GROUP),
                get_room_state(client, hue_username, VALOU_ROOM_GROUP),
            )

    # Determine Roomie status
    now = datetime.now(timezone.utc)
    status, label = determine_valou_status(present, minutes_away, living_room_on, valou_room_on)

    # Track status changes
    history = get_valou_status_history()
    
    if history.get("status") != status:
        since_iso = now.isoformat().replace("+00:00", "Z")
        save_valou_status_history(status, since_iso)
        since = since_iso
    else:
        since = history.get("since")
    
    # Calculate duration
    since_minutes = None
    since_human = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            since_minutes = (now - since_dt).total_seconds() / 60
            since_human = since_dt.strftime("%H:%M")
        except Exception:
            pass

    # Build response with enhanced roomie status
    response = presence_data.copy()
    response["devices"]["roomie"]["enhanced_status"] = status
    response["devices"]["roomie"]["enhanced_label"] = label
    response["devices"]["roomie"]["living_room_on"] = living_room_on
    response["devices"]["roomie"]["valou_room_on"] = valou_room_on
    response["devices"]["roomie"]["since"] = since
    response["devices"]["roomie"]["since_minutes"] = round(since_minutes) if since_minutes is not None else None
    response["devices"]["roomie"]["since_human"] = since_human

    return response


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# --------------------------------------------------------------------------
# Static files (HTML frontend)
# --------------------------------------------------------------------------

# Get the static directory path (relative to this file)
STATIC_DIR = Path(__file__).parent.parent.parent / "static"


@app.get("/")
async def index():
    """Serve the main HTML page."""
    return FileResponse(STATIC_DIR / "index.html")


# Mount static files for any additional assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    """Run the server."""
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5031, log_level="info")


if __name__ == "__main__":
    main()

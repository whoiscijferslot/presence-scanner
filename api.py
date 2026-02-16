#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "starlette==0.45.3",
#   "uvicorn==0.34.0",
#   "httpx==0.28.1",
# ]
# ///
"""Presence Scanner API - HTTP endpoint to trigger manual scans and get enhanced status."""

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

DEBOUNCE_SECONDS = 5
last_trigger_time = 0.0

# Paths
STATUS_FILE = Path("/home/sam1902/projects/presence-scanner/www/status.json")
VALOU_STATUS_FILE = Path("/home/sam1902/projects/presence-scanner/www/valou_status.json")
HUE_TOKENS_FILE = Path.home() / ".config/bedwolf/hue-tokens.json"
HUE_BRIDGE_IP = "192.168.1.103"

# Hue room group IDs
LIVING_ROOM_GROUP = "81"
VALOU_ROOM_GROUP = "84"


def load_hue_username() -> str | None:
    """Load Hue API username from bedwolf config."""
    try:
        with HUE_TOKENS_FILE.open() as f:
            data = json.load(f)
            return data.get("username")
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_valou_status_history() -> dict:
    """Load the last known Roomie status and when it changed."""
    try:
        with VALOU_STATUS_FILE.open() as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"status": None, "since": None}


def save_valou_status_history(status: str, since: str) -> None:
    """Save the current Roomie status and timestamp."""
    data = {"status": status, "since": since}
    with VALOU_STATUS_FILE.open("w") as f:
        json.dump(data, f, indent=2)
    VALOU_STATUS_FILE.chmod(0o644)


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
    """
    Determine Roomie's status based on presence and room lights.
    
    Returns (status, label) tuple.
    """
    # Consider "at home" if detected OR away for less than 5 minutes
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
        # Both off
        return "sleeping", "Sleeping"


async def trigger_scan(request):
    """Trigger a manual presence scan."""
    global last_trigger_time
    now = time.time()
    elapsed = now - last_trigger_time

    if elapsed < DEBOUNCE_SECONDS:
        return JSONResponse({
            "status": "debounced",
            "retry_after": DEBOUNCE_SECONDS - elapsed
        }, status_code=429)

    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "systemctl", "start", "presence-scanner.service",
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=2.0)
        last_trigger_time = now
        return JSONResponse({"status": "triggered"})
    except asyncio.TimeoutError:
        last_trigger_time = now
        return JSONResponse({"status": "triggered"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)


async def valou_status(request):
    """Get enhanced Roomie status based on presence + room lights."""
    # Load presence data
    try:
        with STATUS_FILE.open() as f:
            presence_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return JSONResponse({"error": "Presence data unavailable"}, status_code=500)

    roomie = presence_data.get("devices", {}).get("roomie", {})
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
    status, label = determine_valou_status(present, minutes_away, living_room_on, valou_room_on)

    # Track status changes
    now = datetime.now(timezone.utc)
    history = load_valou_status_history()
    
    if history.get("status") != status:
        # Status changed, update the timestamp
        since_iso = now.isoformat().replace("+00:00", "Z")
        save_valou_status_history(status, since_iso)
        since = since_iso
    else:
        since = history.get("since")
    
    # Calculate duration since status change
    since_minutes = None
    since_human = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            since_minutes = (now - since_dt).total_seconds() / 60
            # Format as HH:MM in local time (CET)
            # For simplicity, add 1 hour for CET (this is approximate)
            since_local = since_dt.replace(tzinfo=None)  # Remove tz for formatting
            since_human = since_dt.strftime("%H:%M")
        except Exception:
            pass

    return JSONResponse({
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
    })


async def full_status(request):
    """Get full presence status for all devices + enhanced Roomie status."""
    # Load presence data
    try:
        with STATUS_FILE.open() as f:
            presence_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return JSONResponse({"error": "Presence data unavailable"}, status_code=500)

    roomie = presence_data.get("devices", {}).get("roomie", {})
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
    history = load_valou_status_history()
    
    if history.get("status") != status:
        # Status changed, update the timestamp
        since_iso = now.isoformat().replace("+00:00", "Z")
        save_valou_status_history(status, since_iso)
        since = since_iso
    else:
        since = history.get("since")
    
    # Calculate duration since status change
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

    return JSONResponse(response)


app = Starlette(routes=[
    Route("/scan", trigger_scan, methods=["POST"]),
    Route("/roomie-status", valou_status, methods=["GET"]),
    Route("/status", full_status, methods=["GET"]),
])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5031, log_level="warning")

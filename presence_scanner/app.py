"""FastAPI application for presence scanner."""

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from .config import settings
from .database import get_all_device_states, get_recent_new_devices, init_db
from .hue import get_hue_service
from .models import (
    DeviceStatus,
    EnhancedDeviceStatus,
    HealthResponse,
    NewDeviceEvent,
    PresenceResponse,
    ScanTriggerResponse,
)
from .new_device_monitor import run_new_device_watch
from .scanner import run_scan

TRIGGER_DEBOUNCE = 5
NEW_DEVICE_WATCH_RESTART_DELAY = 10

# Module-level state
_last_trigger_time: float = 0.0
_scanner_task: asyncio.Task[None] | None = None
_new_device_task: asyncio.Task[None] | None = None


async def background_scanner() -> None:
    """Background task that runs scans periodically."""
    while True:
        try:
            await run_scan()
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, ValueError):
            # Catch expected scan failures: network errors, state errors, parsing errors
            logger.exception("Scan failed")
        await asyncio.sleep(settings.scan_interval)


async def background_new_device_watch() -> None:
    """Background task that watches for devices never seen before.

    ``run_new_device_watch`` already loops (and tolerates transient router
    errors) forever by itself; this wrapper only restarts it, after a short
    delay, if it ever exits due to an unexpected error.
    """
    while True:
        try:
            await run_new_device_watch()
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, ValueError):
            logger.exception("New-device watch crashed; restarting")
            await asyncio.sleep(NEW_DEVICE_WATCH_RESTART_DELAY)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown events."""
    global _scanner_task, _new_device_task  # noqa: PLW0603

    init_db()
    logger.info("Database initialized")

    _scanner_task = asyncio.create_task(background_scanner())
    logger.info(f"Background scanner started (interval: {settings.scan_interval}s)")

    _new_device_task = asyncio.create_task(background_new_device_watch())
    logger.info(
        "New-device watch started "
        f"(interval: {settings.new_device_poll_interval}s)",
    )

    yield

    for task in (_scanner_task, _new_device_task):
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    logger.info("Scanner stopped")


app = FastAPI(
    title="Presence Scanner",
    version="2.0.0",
    lifespan=lifespan,
)


@app.post("/api/scan")
async def trigger_scan(background_tasks: BackgroundTasks) -> ScanTriggerResponse:
    """Trigger a manual presence scan."""
    global _last_trigger_time  # noqa: PLW0603

    now = time.time()
    elapsed = now - _last_trigger_time

    if elapsed < TRIGGER_DEBOUNCE:
        raise HTTPException(
            status_code=429,
            detail=ScanTriggerResponse(
                status="debounced",
                retry_after=TRIGGER_DEBOUNCE - elapsed,
            ).model_dump(),
        )

    _last_trigger_time = now
    background_tasks.add_task(run_scan)
    return ScanTriggerResponse(status="triggered")


@app.get("/api/status")
async def full_status() -> PresenceResponse:
    """Get full presence status for all devices.

    The device configured via ``HUE_ENHANCED_DEVICE_ID`` (if any, and if it's
    actually being tracked) gets an additional light-based enhanced status;
    every other device gets plain presence status.
    """
    presence_data = get_all_device_states()
    hue_service = get_hue_service()
    enhanced_device_id = settings.hue.enhanced_device_id

    devices: dict[str, DeviceStatus | EnhancedDeviceStatus] = {}

    for device_id, device_data in presence_data.devices.items():
        if device_id == enhanced_device_id and enhanced_device_id:
            enhanced = await hue_service.get_enhanced_status(
                is_present=device_data.present,
                last_online=device_data.last_online,
            )
            devices[device_id] = EnhancedDeviceStatus(
                name=device_data.name,
                present=device_data.present,
                last_online=device_data.last_online,
                last_online_human=device_data.last_online_human,
                enhanced_status=enhanced.enhanced_status,
                enhanced_label=enhanced.enhanced_label,
                living_room_on=enhanced.living_room_on,
                secondary_room_on=enhanced.secondary_room_on,
                since=enhanced.since,
                since_minutes=enhanced.since_minutes,
                since_human=enhanced.since_human,
            )
        else:
            devices[device_id] = DeviceStatus(
                name=device_data.name,
                present=device_data.present,
                last_online=device_data.last_online,
                last_online_human=device_data.last_online_human,
            )

    return PresenceResponse(
        scan_time=presence_data.scan_time,
        scan_time_human=presence_data.scan_time_human,
        devices=devices,
    )


@app.get("/api/health")
async def health() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.get("/api/new-devices")
async def new_devices(limit: int = 50) -> list[NewDeviceEvent]:
    """Devices never seen before this monitor recorded them, newest first."""
    return get_recent_new_devices(limit)


STATIC_DIR = Path(__file__).parent.parent / "static"


@app.get("/")
async def index() -> FileResponse:
    """Serve the main HTML page."""
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def main() -> None:
    """Run the server."""
    uvicorn.run(app, host="127.0.0.1", port=5031, log_level="info")


if __name__ == "__main__":
    main()

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
from .database import get_all_device_states, init_db
from .hue import HueService, get_hue_service
from .models import (
    DeviceStatus,
    HealthResponse,
    PresenceResponse,
    ScanTriggerResponse,
    ValouEnhancedStatus,
    ValouStatusResponse,
)
from .scanner import run_scan

TRIGGER_DEBOUNCE = 5

# Module-level state
_last_trigger_time: float = 0.0
_scanner_task: asyncio.Task[None] | None = None


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


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown events."""
    global _scanner_task  # noqa: PLW0603

    init_db()
    logger.info("Database initialized")

    _scanner_task = asyncio.create_task(background_scanner())
    logger.info(f"Background scanner started (interval: {settings.scan_interval}s)")

    yield

    if _scanner_task:
        _scanner_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _scanner_task
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


@app.get("/api/roomie-status")
async def valou_status(
    hue_service: Annotated[HueService, Depends(get_hue_service)],
) -> ValouStatusResponse:
    """Get enhanced Roomie status based on presence + room lights."""
    presence_data = get_all_device_states()

    roomie = presence_data.devices.get("roomie")
    if not roomie:
        raise HTTPException(status_code=500, detail="Roomie data missing")

    enhanced = await hue_service.get_enhanced_valou_status(
        is_present=roomie.present,
        last_online=roomie.last_online,
    )

    return ValouStatusResponse(
        status=enhanced.enhanced_status,
        label=enhanced.enhanced_label,
        present=roomie.present,
        last_online=roomie.last_online,
        minutes_away=enhanced.minutes_away,
        living_room_on=enhanced.living_room_on,
        valou_room_on=enhanced.valou_room_on,
        since=enhanced.since,
        since_minutes=enhanced.since_minutes,
        since_human=enhanced.since_human,
    )


@app.get("/api/status")
async def full_status(
    hue_service: Annotated[HueService, Depends(get_hue_service)],
) -> PresenceResponse:
    """Get full presence status for all devices + enhanced Roomie status."""
    presence_data = get_all_device_states()

    roomie = presence_data.devices.get("roomie")
    if not roomie:
        raise HTTPException(status_code=500, detail="Roomie data missing")

    enhanced = await hue_service.get_enhanced_valou_status(
        is_present=roomie.present,
        last_online=roomie.last_online,
    )

    devices: dict[str, DeviceStatus | ValouEnhancedStatus] = {}

    for device_id, device_data in presence_data.devices.items():
        if device_id == "roomie":
            devices[device_id] = ValouEnhancedStatus(
                name=device_data.name,
                present=device_data.present,
                last_online=device_data.last_online,
                last_online_human=device_data.last_online_human,
                enhanced_status=enhanced.enhanced_status,
                enhanced_label=enhanced.enhanced_label,
                living_room_on=enhanced.living_room_on,
                valou_room_on=enhanced.valou_room_on,
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

#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "starlette==0.45.3",
#   "uvicorn==0.34.0",
# ]
# ///
"""Presence Scanner API - HTTP endpoint to trigger manual scans."""

import asyncio
import time
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

DEBOUNCE_SECONDS = 5
last_trigger_time = 0.0


async def trigger_scan(request):
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


app = Starlette(routes=[Route("/scan", trigger_scan, methods=["POST"])])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5031, log_level="warning")

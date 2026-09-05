"""Philips Hue integration service.

The bridge is reached over its v1 HTTP API, which is port-forwarded on the
router's WAN IP (see :class:`presence_scanner.config.HueConfig`).
"""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

import httpx
from loguru import logger

from .config import settings
from .database import (
    DISPLAY_TZ,
    get_enhanced_status_history,
    save_enhanced_status_history,
)
from .models import EnhancedPresenceData, RoomStates

PresenceStatus = Literal["downstairs", "around", "awake", "sleeping", "away"]

# Threshold for considering someone "effectively home" even if not detected
EFFECTIVELY_HOME_MINUTES = 5


@dataclass
class StatusInput:
    """Input for status determination."""

    is_present: bool
    minutes_away: float
    room_states: RoomStates


class HueClientProtocol(Protocol):
    """Protocol for Hue API client."""

    async def get_room_state(self, group_id: str) -> bool:
        """Check if any light in a room is on."""
        ...


class HueClient:
    """Client for the Philips Hue v1 HTTP API."""

    def __init__(self, base_url: str, username: str | None) -> None:
        """Initialize Hue client with the (port-forwarded) API base URL."""
        self.base_url = base_url.rstrip("/")
        self.username = username

    async def get_room_state(self, group_id: str) -> bool:
        """Check if any light in a room is on."""
        if not self.username:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/api/{self.username}/groups/{group_id}",
                    timeout=settings.hue.timeout,
                )
                data = response.json()
                return bool(data.get("state", {}).get("any_on", False))
        except httpx.HTTPError as e:
            logger.warning(f"Failed to get room state for group {group_id}: {e}")
            return False


# Hours (in DISPLAY_TZ) each simulated room's lights are "on", used only by
# MockHueClient. Chosen to cycle through every enhanced status once a day:
# sleeping (0-5) -> awake (6-7) -> downstairs (8-18) -> around (19-22)
# -> awake (23) -> sleeping (0...).
_MOCK_LIVING_ON_HOURS = frozenset(range(8, 23))
_MOCK_SECONDARY_ON_HOURS = frozenset({6, 7, 19, 20, 21, 22, 23})


class MockHueClient:
    """Deterministic, time-of-day simulated Hue client.

    Lets the enhanced-status feature (and its Downstairs / Around / Awake /
    Sleeping / Away states) be exercised and demonstrated without any real
    smart lights. Selected automatically when ``HUE_USERNAME`` is unset, or
    explicitly via ``HUE_BACKEND=mock`` (see ``.env.example``).
    """

    def __init__(
        self,
        *,
        living_room_group: str,
        secondary_room_group: str,
        force_hour: int | None = None,
    ) -> None:
        """Initialize with the configured group IDs, used to tell rooms apart."""
        self._living_room_group = living_room_group
        self._secondary_room_group = secondary_room_group
        self._force_hour = force_hour

    def _hour(self) -> int:
        """Return the simulated hour-of-day (forced, or the current time)."""
        if self._force_hour is not None:
            return self._force_hour
        return datetime.now(DISPLAY_TZ).hour

    async def get_room_state(self, group_id: str) -> bool:
        """Return a simulated on/off state for the given room group."""
        hour = self._hour()
        if group_id == self._living_room_group:
            return hour in _MOCK_LIVING_ON_HOURS
        if group_id == self._secondary_room_group:
            return hour in _MOCK_SECONDARY_ON_HOURS
        return False


class HueService:
    """Service for Hue-based presence detection."""

    def __init__(self, client: HueClientProtocol) -> None:
        """Initialize Hue service with client."""
        self.client = client

    @staticmethod
    def determine_status(status_input: StatusInput) -> tuple[PresenceStatus, str]:
        """
        Determine the tracked user's status based on presence and room lights.

        Returns (status, label) tuple.
        """
        is_effectively_home = (
            status_input.is_present
            or status_input.minutes_away < EFFECTIVELY_HOME_MINUTES
        )
        living_on = status_input.room_states.living_room_on
        secondary_on = status_input.room_states.secondary_room_on

        if not is_effectively_home:
            return "away", "Away"
        if living_on and not secondary_on:
            return "downstairs", "Downstairs"
        if living_on and secondary_on:
            return "around", "Around"
        if not living_on and secondary_on:
            return "awake", "Awake"
        return "sleeping", "Sleeping"

    async def get_room_states(self) -> RoomStates:
        """Get living room and secondary room light states (queried concurrently).

        Running both requests together means an unreachable bridge costs one
        timeout, not two, keeping ``/api/status`` responsive when Hue is down.
        """
        living_room_on, secondary_room_on = await asyncio.gather(
            self.client.get_room_state(settings.hue.living_room_group),
            self.client.get_room_state(settings.hue.secondary_room_group),
        )
        return RoomStates(
            living_room_on=living_room_on,
            secondary_room_on=secondary_room_on,
        )

    async def get_enhanced_status(
        self,
        *,
        is_present: bool,
        last_online: str | None,
    ) -> EnhancedPresenceData:
        """Get the enhanced (room-light-based) status for the tracked device."""
        # Calculate minutes away
        minutes_away = float("inf")
        if last_online:
            try:
                last_online_dt = datetime.fromisoformat(last_online)
                now = datetime.now(UTC)
                minutes_away = (now - last_online_dt).total_seconds() / 60
            except ValueError:
                pass

        # Get room states
        room_states = await self.get_room_states()

        # Determine status
        now = datetime.now(UTC)
        status_input = StatusInput(
            is_present=is_present,
            minutes_away=minutes_away,
            room_states=room_states,
        )
        status, label = self.determine_status(status_input)

        # Track status changes
        history = get_enhanced_status_history()

        since: str | None
        if history.status != status:
            since = now.isoformat().replace("+00:00", "Z")
            save_enhanced_status_history(status, since)
        else:
            since = history.since

        # Calculate duration
        since_minutes: int | None = None
        since_human: str | None = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                since_minutes = round((now - since_dt).total_seconds() / 60)
                since_human = since_dt.astimezone(DISPLAY_TZ).strftime("%H:%M")
            except ValueError:
                pass

        return EnhancedPresenceData(
            enhanced_status=status,
            enhanced_label=label,
            living_room_on=room_states.living_room_on,
            secondary_room_on=room_states.secondary_room_on,
            since=since,
            since_minutes=since_minutes,
            since_human=since_human,
            minutes_away=minutes_away if minutes_away != float("inf") else None,
        )


def get_hue_service() -> HueService:
    """Factory function to create HueService with the configured backend."""
    client: HueClientProtocol
    if settings.hue.backend == "mock":
        client = MockHueClient(
            living_room_group=settings.hue.living_room_group,
            secondary_room_group=settings.hue.secondary_room_group,
            force_hour=settings.hue.mock_force_hour,
        )
    else:
        client = HueClient(settings.hue.base_url, settings.hue.username)
    return HueService(client)

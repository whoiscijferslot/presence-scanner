"""Philips Hue integration service."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

import httpx
from loguru import logger

from .config import settings
from .database import get_valou_status_history, save_valou_status_history

ValouStatus = Literal["downstairs", "around", "awake", "sleeping", "away"]

# Threshold for considering someone "effectively home" even if not detected
EFFECTIVELY_HOME_MINUTES = 5


@dataclass
class RoomStates:
    """State of room lights."""

    living_room_on: bool
    valou_room_on: bool


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
    """Client for Philips Hue API."""

    def __init__(self, bridge_ip: str, username: str | None) -> None:
        """Initialize Hue client."""
        self.bridge_ip = bridge_ip
        self.username = username

    async def get_room_state(self, group_id: str) -> bool:
        """Check if any light in a room is on."""
        if not self.username:
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://{self.bridge_ip}/api/{self.username}/groups/{group_id}",
                    timeout=5.0,
                )
                data = response.json()
                return bool(data.get("state", {}).get("any_on", False))
        except httpx.HTTPError as e:
            logger.warning(f"Failed to get room state for group {group_id}: {e}")
            return False


class HueService:
    """Service for Hue-based presence detection."""

    def __init__(self, client: HueClientProtocol) -> None:
        """Initialize Hue service with client."""
        self.client = client

    @staticmethod
    def load_hue_username() -> str | None:
        """Load Hue API username from config file."""
        try:
            with settings.hue_tokens_file.open() as f:
                data = json.load(f)
                return str(data.get("username")) if data.get("username") else None
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.debug(f"Could not load Hue tokens: {e}")
            return None

    @staticmethod
    def determine_status(status_input: StatusInput) -> tuple[ValouStatus, str]:
        """
        Determine Roomie's status based on presence and room lights.

        Returns (status, label) tuple.
        """
        is_effectively_home = (
            status_input.is_present
            or status_input.minutes_away < EFFECTIVELY_HOME_MINUTES
        )
        living_on = status_input.room_states.living_room_on
        valou_on = status_input.room_states.valou_room_on

        if not is_effectively_home:
            return "away", "Away"
        if living_on and not valou_on:
            return "downstairs", "Downstairs"
        if living_on and valou_on:
            return "around", "Around"
        if not living_on and valou_on:
            return "awake", "Awake"
        return "sleeping", "Sleeping"

    async def get_room_states(self) -> RoomStates:
        """Get living room and Roomie room light states."""
        living_room_on = await self.client.get_room_state(settings.living_room_group)
        valou_room_on = await self.client.get_room_state(settings.valou_room_group)
        return RoomStates(living_room_on=living_room_on, valou_room_on=valou_room_on)

    async def get_enhanced_valou_status(
        self,
        *,
        is_present: bool,
        last_online: str | None,
    ) -> dict[str, str | bool | int | float | None]:
        """Get enhanced Roomie status with room light info."""
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
        history = get_valou_status_history()

        if history.get("status") != status:
            since_iso = now.isoformat().replace("+00:00", "Z")
            save_valou_status_history(status, since_iso)
            since = since_iso
        else:
            since = history.get("since")

        # Calculate duration
        since_minutes: int | None = None
        since_human: str | None = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                since_minutes = round((now - since_dt).total_seconds() / 60)
                since_human = since_dt.strftime("%H:%M")
            except ValueError:
                pass

        return {
            "enhanced_status": status,
            "enhanced_label": label,
            "living_room_on": room_states.living_room_on,
            "valou_room_on": room_states.valou_room_on,
            "since": since,
            "since_minutes": since_minutes,
            "since_human": since_human,
            "minutes_away": minutes_away if minutes_away != float("inf") else None,
        }


def get_hue_service() -> HueService:
    """Factory function to create HueService with configured client."""
    username = HueService.load_hue_username()
    client = HueClient(settings.hue_bridge_ip, username)
    return HueService(client)

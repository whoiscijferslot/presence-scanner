"""Pydantic models for API responses and internal data."""

from typing import Literal

from pydantic import BaseModel

# =============================================================================
# Internal models (used within the application)
# =============================================================================


class DeviceState(BaseModel):
    """Internal state of a device from database."""

    present: bool
    last_online: str | None


class DeviceData(BaseModel):
    """Full device data from database."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None


class PresenceData(BaseModel):
    """All device states from database."""

    scan_time: str | None
    scan_time_human: str | None
    devices: dict[str, DeviceData]


class EnhancedStatusHistory(BaseModel):
    """Enhanced (light-based) status history from database."""

    status: str | None
    since: str | None


class NewDeviceEvent(BaseModel):
    """First-seen/last-seen record for a device never tracked by name.

    Used both internally (new_device_monitor) and as an API response model.
    """

    mac: str
    ip: str
    name: str
    connection: str
    first_seen: str
    first_seen_human: str | None
    last_seen: str
    last_seen_human: str | None


class RoomStates(BaseModel):
    """State of room lights from Hue."""

    living_room_on: bool
    secondary_room_on: bool


class EnhancedPresenceData(BaseModel):
    """Enhanced presence status with Hue (light-state) integration."""

    enhanced_status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    enhanced_label: str
    living_room_on: bool
    secondary_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None
    minutes_away: float | None


# =============================================================================
# API response models
# =============================================================================


class DeviceStatus(BaseModel):
    """Status of a single device (API response)."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None


class EnhancedDeviceStatus(BaseModel):
    """Enhanced status for a device with Hue integration (API response)."""

    name: str
    present: bool
    last_online: str | None
    last_online_human: str | None
    enhanced_status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    enhanced_label: str
    living_room_on: bool
    secondary_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None


class PresenceResponse(BaseModel):
    """Full presence status response."""

    scan_time: str | None
    scan_time_human: str | None
    devices: dict[str, DeviceStatus | EnhancedDeviceStatus]


class EnhancedStatusResponse(BaseModel):
    """Single-device enhanced status response."""

    status: Literal["downstairs", "around", "awake", "sleeping", "away"]
    label: str
    present: bool
    last_online: str | None
    minutes_away: float | None
    living_room_on: bool
    secondary_room_on: bool
    since: str | None
    since_minutes: int | None
    since_human: str | None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    timestamp: str


class ScanTriggerResponse(BaseModel):
    """Response for scan trigger endpoint."""

    status: str
    retry_after: float | None = None

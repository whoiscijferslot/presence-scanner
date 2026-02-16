"""SQLite database operations for presence scanner."""

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from loguru import logger

from .config import settings


@dataclass
class DeviceUpdate:
    """Data for updating a device state."""

    device_id: str
    name: str
    ip: str
    mac: str
    present: bool
    last_online: str | None
    scan_time: str


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(settings.db_file)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database schema."""
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                present INTEGER NOT NULL DEFAULT 0,
                last_online TEXT,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                device_id TEXT NOT NULL,
                present INTEGER NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(device_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS valou_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                status TEXT,
                since TEXT
            )
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS limit_scan_history
            AFTER INSERT ON scans
            BEGIN
                DELETE FROM scans WHERE id IN (
                    SELECT id FROM scans
                    WHERE device_id = NEW.device_id
                    ORDER BY id DESC
                    LIMIT -1 OFFSET 1000
                );
            END
        """)
        conn.commit()
        logger.debug("Database schema initialized")
    finally:
        conn.close()


def get_device_state(device_id: str) -> dict[str, bool | str | None] | None:
    """Get current state of a device from database."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT present, last_online FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        if row:
            return {"present": bool(row["present"]), "last_online": row["last_online"]}
        return None
    finally:
        conn.close()


DevicesDict = dict[str, dict[str, str | bool | None]]
PresenceData = dict[str, str | DevicesDict | None]


def get_all_device_states() -> PresenceData:
    """Get current state of all devices."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT MAX(updated_at) as scan_time FROM devices"
        ).fetchone()
        scan_time: str | None = row["scan_time"] if row else None

        devices: DevicesDict = {}
        for row in conn.execute("SELECT * FROM devices"):
            device_id: str = row["device_id"]
            devices[device_id] = {
                "name": row["name"],
                "present": bool(row["present"]),
                "last_online": row["last_online"],
                "last_online_human": format_time_human(row["last_online"]),
            }

        return {
            "scan_time": scan_time,
            "scan_time_human": format_time_human(scan_time),
            "devices": devices,
        }
    finally:
        conn.close()


def update_device_state(update: DeviceUpdate) -> None:
    """Update device state in database."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO devices
                (device_id, name, ip, mac, present, last_online, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                ip = excluded.ip,
                mac = excluded.mac,
                present = excluded.present,
                last_online = excluded.last_online,
                updated_at = excluded.updated_at
            """,
            (
                update.device_id,
                update.name,
                update.ip,
                update.mac,
                int(update.present),
                update.last_online,
                update.scan_time,
            ),
        )

        conn.execute(
            "INSERT INTO scans (scan_time, device_id, present) VALUES (?, ?, ?)",
            (update.scan_time, update.device_id, int(update.present)),
        )
        conn.commit()
    finally:
        conn.close()


def get_valou_status_history() -> dict[str, str | None]:
    """Get the last known Roomie status."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT status, since FROM valou_status WHERE id = 1"
        ).fetchone()
        if row:
            return {"status": row["status"], "since": row["since"]}
        return {"status": None, "since": None}
    finally:
        conn.close()


def save_valou_status_history(status: str, since: str) -> None:
    """Save the current Roomie status."""
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO valou_status (id, status, since) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                since = excluded.since
            """,
            (status, since),
        )
        conn.commit()
    finally:
        conn.close()


def format_time_human(iso_time: str | None) -> str | None:
    """Convert ISO time to human readable format."""
    if not iso_time:
        return None
    try:
        dt = datetime.fromisoformat(iso_time)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso_time

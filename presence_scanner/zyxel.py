"""Zyxel router API client for presence detection.

Uses AES-RSA hybrid encryption matching the router's web interface.
This is the most reliable detection method since the router tracks
all connected devices regardless of whether they respond to pings.
"""

import base64
import json
import os
from dataclasses import dataclass, field

import httpx
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from loguru import logger
from pydantic import BaseModel


class ZyxelDevice(BaseModel):
    """A device connected to the Zyxel router."""

    mac: str
    ip: str
    hostname: str
    active: bool
    connection_type: str


class ZyxelConfig(BaseModel):
    """Configuration for Zyxel router API."""

    router_ip: str = "192.168.1.1"
    username: str = "admin"
    password: str = ""
    timeout: int = 10


@dataclass
class ZyxelSession:
    """Active session with the Zyxel router."""

    session_key: str
    aes_key_b64: str
    client: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=10))

    def close(self) -> None:
        """Close the HTTP client."""
        self.client.close()


def _aes_encrypt(data: str, key: bytes, iv: bytes) -> str:
    """AES-CBC encrypt with PKCS7 padding, return base64."""
    cipher = AES.new(key, AES.MODE_CBC, iv[:16])
    padded = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()


def _aes_decrypt(data_b64: str, key_b64: str, iv_b64: str) -> str:
    """AES-CBC decrypt with PKCS7 unpadding."""
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = base64.b64decode(data_b64)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode()


def _rsa_encrypt(data: bytes, pubkey_pem: str) -> str:
    """RSA encrypt with PKCS1 v1.5, return base64."""
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode()


def login(config: ZyxelConfig) -> ZyxelSession | None:
    """
    Authenticate with the Zyxel router.

    Returns a ZyxelSession on success, None on failure.
    """
    client = httpx.Client(timeout=config.timeout)

    try:
        # Get RSA public key
        r = client.get(f"http://{config.router_ip}/getRSAPublickKey")
        pubkey = r.json().get("RSAPublicKey")
        if not pubkey:
            logger.error("Failed to get RSA public key from router")
            return None

        # Generate random AES key and IV
        aes_key = os.urandom(32)
        iv = os.urandom(32)
        aes_key_b64 = base64.b64encode(aes_key).decode()
        iv_b64 = base64.b64encode(iv).decode()

        # Build the login payload
        inner_payload = {
            "Input_Account": config.username,
            "Input_Passwd": base64.b64encode(config.password.encode()).decode(),
            "currLang": "en",
            "RememberPassword": 0,
        }
        inner_json = json.dumps(inner_payload)

        # Encrypt with AES
        content = _aes_encrypt(inner_json, aes_key, iv)

        # RSA encrypt the AES key
        encrypted_key = _rsa_encrypt(aes_key_b64.encode(), pubkey)

        # Send login request
        outer_payload = {"content": content, "key": encrypted_key, "iv": iv_b64}
        r = client.post(f"http://{config.router_ip}/UserLogin", json=outer_payload)
        response = r.json()

        # Decrypt response
        if "content" not in response or "iv" not in response:
            logger.error(f"Unexpected login response: {response}")
            return None

        decrypted = _aes_decrypt(response["content"], aes_key_b64, response["iv"])
        result = json.loads(decrypted)

        if result.get("result") != "ZCFG_SUCCESS":
            logger.error(f"Login failed: {result.get('result')}")
            return None

        session_key = result.get("sessionkey")
        if not session_key:
            logger.error("No session key in login response")
            return None

        logger.debug("Successfully logged in to Zyxel router")
        return ZyxelSession(
            session_key=session_key,
            aes_key_b64=aes_key_b64,
            client=client,
        )

    except (httpx.RequestError, json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error(f"Failed to login to Zyxel router: {e}")
        client.close()
        return None


def get_connected_devices(
    session: ZyxelSession, router_ip: str = "192.168.1.1"
) -> list[ZyxelDevice]:
    """
    Get list of devices connected to the router.

    Returns empty list on failure.
    """
    try:
        r = session.client.get(
            f"http://{router_ip}/cgi-bin/DAL?oid=lanhosts",
            headers={"CSRFToken": session.session_key},
        )
        response = r.json()

        if "content" not in response or "iv" not in response:
            logger.warning(f"Unexpected lanhosts response: {response}")
            return []

        decrypted = _aes_decrypt(
            response["content"], session.aes_key_b64, response["iv"]
        )
        data = json.loads(decrypted)

        if data.get("result") != "ZCFG_SUCCESS":
            logger.warning(f"Failed to get lanhosts: {data.get('result')}")
            return []

        devices: list[ZyxelDevice] = []
        for obj in data.get("Object", []):
            devices.extend(
                ZyxelDevice(
                    mac=host.get("PhysAddress", "").lower(),
                    ip=host.get("IPAddress", ""),
                    hostname=host.get("HostName", ""),
                    active=host.get("Active", False),
                    connection_type=host.get("X_ZYXEL_ConnectionType", "Unknown"),
                )
                for host in obj.get("lanhosts", [])
            )

    except (httpx.RequestError, json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error(f"Failed to get connected devices: {e}")
        return []
    else:
        return devices


def check_device_presence(
    config: ZyxelConfig, mac_addresses: dict[str, str]
) -> dict[str, bool]:
    """
    Check presence of devices by MAC address.

    Args:
        config: Zyxel router configuration
        mac_addresses: Dict of device_id -> MAC address (lowercase, colon-separated)

    Returns:
        Dict of device_id -> is_present
    """
    # Login to router
    session = login(config)
    if not session:
        logger.warning("Could not login to Zyxel router, returning empty results")
        return dict.fromkeys(mac_addresses, False)

    try:
        # Get connected devices
        devices = get_connected_devices(session, config.router_ip)

        # Build set of active MACs
        active_macs = {d.mac.lower() for d in devices if d.active}

        # Check each device
        return {
            device_id: mac.lower() in active_macs
            for device_id, mac in mac_addresses.items()
        }

    finally:
        session.close()

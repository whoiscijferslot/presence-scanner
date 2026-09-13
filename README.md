# CVE-2026-6952: Zyxel EX5601-T1 Post-Auth Command Injection

Lab-validated exploitation chain demonstrating **full router compromise** → **LAN presence sensor defeat** → **home network takeover**.

---

## Quick Start

```bash
# Clone and enter the repo
git clone <your-repo-url>
cd presence-scanner

# Start the mock (EX5601-T1 simulator on localhost:8812)
uv run homelab/mock_zyxel_vuln_6952.py &

# Run the PoC (dry-run first, then with --yes)
uv run poc/poc_f_cve_2026_6952_lab.py              # dry-run: chain up to inject, then abort
uv run poc/poc_f_cve_2026_6952_lab.py --yes        # execute: inject → RCE proof → restore
```

**Expected output:**
```
*** RCE CONFIRMED: id + uname -a + hostname captured from the sink ***
```

---

## The Exploitation Chain

```
GET /getRSAPublickKey → RSA+AES login via POST /UserLogin → 
read firmware version → if unpatched: inject into LogServer → 
command execution as root → full LAN pivot → presence sensor defeat
```

See [`REPORT.md`](REPORT.md) for the complete technical breakdown.

---

## Lab Credentials

The mock and PoC read the **same** two environment variables so they stay in sync:

```bash
export LAB_USER=""   # demo default: admin
export LAB_PASS=""   # demo default: LabPass#2026
```

Precedence: `--user`/`--pass` CLI flags > env > demo defaults. The PoC **never reads `ZYXEL_PASS`** — the real router password stays scoped to live targets.

Placeholders: [`poc/.env.example`](poc/.env.example).

---

## Dependencies

- `uv` (PEP 723 inline script deps) or plain `python3` with packages from [`poc/requirements.txt`](poc/requirements.txt)
- Repo root must be importable (`cd ~/Downloads/presence-scanner`), because the PoC imports `presence_scanner`

---

## Evidence

- Raw evidence: `poc/evidence/pocF_cve_2026_6952_lab_*.jsonl` (git-ignored)
- Sanitized copies: `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl` (committable, publish-ready)

Generate sanitized copies with the helper:
```bash
python3 sanitize_evidence.py poc/evidence/pocF_cve_2026_6952_lab_<timestamp>.jsonl zvezdochka Janes-MacBook-Pro
```

---

## LinkedIn Post

[`poc/LINKEDIN_CVE_2026_6952_EXPLOIT_CHAIN.md`](poc/LINKEDIN_CVE_2026_6952_EXPLOIT_CHAIN.md) — the exploitation chain documentation for social sharing.

---

## Other POCs (Archived)

F1-F5 POCs (session replay, slot exhaustion, Hue probe, login storm, WAN edge) are archived in [`poc/archive/`](poc/archive/) for reference.

---

## License

MIT — for authorized security assessments and research.

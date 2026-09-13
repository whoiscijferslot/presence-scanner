# POC: CVE-2026-6952 Lab Proof-of-Concept

Lab-validated exploitation chain for Zyxel EX5601-T1 post-auth LogServer command injection.

---

## Safety Matrix

| POC | Default behavior | Network? | Touches router/Hue? | Gate |
|-----|------------------|----------|--------------------|------|
| `poc_f_cve_2026_6952_lab.py` | dry-run unless `--yes` | localhost only (mock :8812) | **no** (never touches router/Hue) | `--yes` |

---

## Setup

Environment comes from `LAB_USER` / `LAB_PASS` (see [`.env.example`](.env.example)). Run from the repo root so `presence_scanner` imports:

```bash
cd ~/Downloads/presence-scanner
uv run poc/poc_f_cve_2026_6952_lab.py ...   # Mac with uv (PEP 723 headers honored)
# or:
PYTHONPATH=$PWD python3 poc/poc_f_cve_2026_6952_lab.py ...
```

### Dependencies

- `uv` (PEP 723 inline script deps) or plain `python3` with packages from [`requirements.txt`](requirements.txt)
- Repo root must be importable (`cd ~/Downloads/presence-scanner`), because the PoC imports `presence_scanner`

### Lab Credentials

The lab mock (`homelab/mock_zyxel_vuln_6952.py`) and PoC resolve credentials with the same precedence, so mock and PoC always stay in sync:

1. `--user` / `--pass` CLI flags (PoC only), then
2. `$LAB_USER` / `$LAB_PASS` environment variables, then
3. demo defaults `admin` / `LabPass#2026`.

POC **never reads `ZYXEL_USER` / `ZYXEL_PASS`** — it only ever talks to the local mock, never to the router. Copy `.env.example` to `.env` if you want to pin the lab credentials explicitly.

---

## Runs

```bash
# Start the mock (EX5601-T1 simulator on 127.0.0.1:8812)
uv run homelab/mock_zyxel_vuln_6952.py &     # Ctrl-C / kill %1 to stop

# Dry-run: full chain up to the inject write, then aborts
uv run poc/poc_f_cve_2026_6952_lab.py

# Execute: quote-break inject → RCE proof file → restore
uv run poc/poc_f_cve_2026_6952_lab.py --yes
```

**Expected output (with --yes):**
```
=== Verification ===
proof file content (XXX bytes):
uid=0(root) gid=0(root) groups=0(root)
Linux <hostname> 6.x.x ...
<hostname>

*** RCE CONFIRMED: id + uname -a + hostname captured from the sink ***

=== Restore ===
restore result: OK ...
mock state after restore: LogServer='' port=514

evidence file: poc/evidence/pocF_cve_2026_6952_lab_<timestamp>Z.jsonl
```

---

## Evidence

Measured results are in `evidence/`:
- Raw: `pocF_cve_2026_6952_lab_*.jsonl` (git-ignored)
- Sanitized: `pocF_cve_2026_6952_lab_*.public.jsonl` (committable, publish-ready)

Raw evidence is git-ignored; operator-reviewed `*.public.jsonl` sanitized copies are the committable, publish-ready artifacts.

---

## Notes

- POC is fully offline: the mock listens on `127.0.0.1:8812`, and the PoC refuses to run against anything but loopback by default (use `--allow-nonlocal` ONLY for a container/VM interface holding your own mock).
- POC exists in two variants: the committed lab PoC in this repo (mock-only) and the Mac-only `poc_f_logserver_rce.py` live-target variant, which is intentionally **not** in this repo.
- POC evidence: raw `pocF_cve_2026_6952_lab_*.jsonl` are git-ignored; the sanitized `*.public.jsonl` copies are the committable, publish-ready artifacts.
- Disposable local artifacts to delete when back on the Mac: `/tmp/presence-scanner/poc_probe_nl.txt` (if it exists).

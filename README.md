# Presence Scanner — Tracking People, Inferring Sleep, and the Router That Knows Too Much

**No exploits. No malware. Just a router password someone already has — and
that's enough to track where you are and when you sleep.**

Someone I know built exactly this to spy on a roommate — Wi-Fi presence
tracking plus sleep/wake inference from smart-light activity. With my own
roommate's full knowledge and consent, I rebuilt it as a clean proof-of-concept,
scrubbed every credential and identifier, and I'm sharing it — not as a how-to,
but to show how little it takes to build, and how little it takes to defend
against.

---

### What this actually does

**1. Tracks people on the network.** The router's admin panel exposes every
connected device's MAC address — no packet sniffing required. Most phones keep
a stable MAC address on "trusted" networks, turning it into a long-term
identifier for a specific person, not just a device. This service polls the
router's **live IPv4 ARP table** remotely (from outside the LAN) and logs
when each tracked MAC appears or disappears.

**2. Infers sleep/wake from smart lights.** Combine Wi-Fi presence with
Philips Hue bridge data (lights on/off per room) and you get a surprisingly
detailed picture of someone's daily routine — Downstairs / Around / Awake /
Sleeping / Away — from credentials a housemate, ex-partner, or landlord may
already have.

**3. The router is the single point of failure.** This repository also
documents [CVE-2026-6952](#2-security-research-cve-2026-6952), a post-auth
command injection in the Zyxel EX5601-T1's LogServer/DAL endpoint. Validated
in the lab as a deterministic chain: **admin credentials → root RCE → LAN
presence-sensor defeat → home-network takeover**. Root on the router means the
attacker can poison the ARP/LAN tables this very scanner polls: every service
that trusts the result — lights, locks, security system — flips to "nobody
home" while the router keeps routing traffic as if nothing happened.

The full threat model, a longer defense checklist for both sides, and how to
spot things like an unrecognized device quietly sitting on your LAN — all in
the sections below.

---

### The two sides of this repository

**§1 The presence-scanner project** — the full walkthrough: how it works,
threat model, why this works, how to defend against this, configuration,
deployment.

**§2 Security research: CVE-2026-6952** — the lab-validated exploitation chain
that turns router RCE into a LAN presence-sensor defeat and home-network
takeover. The router *is* the source of truth for who is home — compromise it,
and the scanner (and every other service that trusts it) lies to you.

Read one, and you understand the other.

**⚠️ To be unambiguous:** Monitoring another person's device presence or
behavior without their knowledge or consent can be illegal (stalking,
harassment, or computer-misuse statutes, depending on jurisdiction),
independent of whether it's also a violation of trust. This project is
published for awareness and defense, not as a how-to for tracking someone
without consent.

---

## Contents

- [1. The presence-scanner project](#1-the-presence-scanner-project)
- [2. Security research: CVE-2026-6952](#2-security-research-cve-2026-6952)
- [3. License](#license)

---

## 1. The presence-scanner project

### How it works

Two data sources, both remote:

1. **Zyxel router API** (HTTPS, `zyxel_client.py`) — the sole presence source.
   A device counts as present if its MAC is in the router's **live IPv4 ARP
   table**. IPv6 neighbour entries (which linger long after a device leaves) and
   the `lanhosts` `Active` flag (which follows the DHCP lease) are deliberately
   ignored. No ping / ARP / nmap on the host itself (it's off-LAN).
   The router allows few concurrent logins, so the session is cached in the DB
   and reused for ~60 minutes (`zyxel_session.py`) rather than re-logging in
   every scan.
2. **Philips Hue bridge** (v1 HTTP API, port-forwarded on the router) — enriches
   one configured device's status from room-light state (Downstairs / Around /
   Awake / Sleeping / Away). Optional: if the bridge is unreachable, or
   `HUE_ENHANCED_DEVICE_ID` is unset, status degrades gracefully.

   **No smart lights? No problem.** With `HUE_USERNAME` unset (the default),
   a deterministic mock backend simulates a full day's light schedule, so the
   enhanced status is fully demoable/testable without any real hardware. See
   `HUE_BACKEND` / `HUE_MOCK_FORCE_HOUR` in `.env.example`.

Other features:

- **SQLite database** for reliable state persistence
- **Debounced** state changes (a second query confirms appear/disappear)
- **Background scanning** every 60 seconds
- **New-device monitoring**: separately from the tracked `DEVICES` list,
  every *active* MAC address the router reports is checked against
  everything this monitor has ever recorded; the first time a MAC is seen,
  it's logged as a new connection and persisted so it's never re-flagged.
  Runs as a background task in the app (`GET /api/new-devices` returns
  recent events) or standalone via `presence-watch-new-devices`
  (see [New device monitor](#new-device-monitor)).
- **Web UI** with retro terminal aesthetic

### Threat model

This tool assumes the operator already has legitimate router-admin (or
smart-home hub) credentials — the same access a housemate, ex-partner,
family member, or landlord commonly ends up with. It is **not** a remote
exploit, does not bypass authentication, and does not work against a network
where the operator has no admin access. That's exactly what makes the
underlying problem hard to fix with a single setting: router-level defenses
like account lockouts, brute-force throttling, and HTTPS-only admin panels
all protect against an *outside* attacker guessing credentials — none of them
protect against someone who already has the password, which is the realistic
threat here.

### Why this works

Nothing here is a router or Hue “exploit,” or requires a security background — 
just five minutes in your router’s admin panel. It only works because of how 
home networks are typically configured by default:

- **Router admin credentials are shared and rarely rotated.** Whoever knows
  the admin login can query the live ARP table (or LAN host list) for every
  device on the network, at any time, from anywhere the panel is reachable.
- **Device MAC addresses are stable.** Most phones only randomize their MAC
  for *new* networks; once joined to a trusted Wi-Fi (like your own home
  network), many devices use a stable, real MAC every time, which makes a
  device a reliable, long-term tracking identifier on that network.
- **Router admin panels and IoT bridges are sometimes exposed to the WAN
  side** (e.g. via port forwarding, DDNS hostnames, or "remote management"
  toggles), which is what let this specific tool run from a host that was
  no longer on the LAN at all.
- **Smart-home device state is legible and often has no per-user access
  control.** Anyone with the Hue bridge's local API key can query every
  light's on/off state, which combined with presence data cheaply proxies
  for a room-level activity/sleep signal.

None of this requires malware, packet sniffing, or breaking into anything —
just admin access to the router (or a bridge/app credential to a shared smart
home hub) that a housemate, ex-partner, family member, or landlord may
already have.

### How to defend against this

If you share a network with people you don't want profiling your
comings, goings, and sleep schedule, no single toggle fixes this — it's a
layered problem. Ordered roughly by impact if you're a **device owner**
without router-admin control:

1. **Turn on private/randomized Wi-Fi addressing for the network**, not just
   "per connection." iOS: *Settings > Wi-Fi > (i) next to the network >
   Private Wi-Fi Address > Rotating* (iOS 17+) or *On*. Android: per-network
   setting under *Wi-Fi > network > Privacy > Use randomized MAC*. A rotating
   MAC breaks the assumption that "this MAC = this person, forever."
2. **Don't accept a static IP / DHCP reservation** for your device unless you
   need it. A reservation is usually created *from* a MAC address the admin
   already has bound to your name — reintroducing exactly the stable
   identifier MAC randomization is trying to remove.
3. **Use a VPN for traffic you consider private.** A VPN doesn't hide that
   your device is *connected* (the router still sees the association), but
   it does stop anyone on the LAN/router from seeing what you do once
   you're on.
4. **Ask for (or set up) client/AP isolation or a separate VLAN/guest
   network per person.** If your device can't be resolved on the same
   broadcast domain as the admin's, it can't show up in *their* ARP table
   at all — the strongest fix, but it requires router support and
   cooperation from whoever administers it.
5. **Treat "who has the router admin password" as a real access-control
   question**, the same way you would for a shared house key. Ask that it be
   rotated when someone moves out, and ask what remote-management/port
   forwarding is enabled.

If you **administer the router or the smart-home hub** (or want to check
what's currently exposed):

- **Disable remote/WAN administration** on the router unless you have a
  specific, time-boxed reason to enable it. If you need remote access, put it
  behind a VPN into the LAN rather than exposing the admin panel or a
  bridge's API directly.
- **Audit port forwarding and UPnP.** Router UIs list active forwards; delete
  anything you don't recognize, and disable UPnP so devices (including a Hue
  bridge) can't silently open new ones.
- **Change default admin credentials**, don't reuse them elsewhere, and
  rotate them whenever household/tenant access changes.
- **Put IoT/smart-home devices on their own VLAN or guest network**, isolated
  from personal devices. This limits both what a compromised IoT device can
  see and what a curious housemate with LAN access can query about your
  lights.
- **Periodically review paired apps/API keys on smart-home bridges** (e.g.
  Hue's *whitelist* of authorized usernames) and revoke ones you don't
  recognize — a Hue v1 API username, once issued, works indefinitely with no
  further prompt on the bridge.
- **Check router logs/connected-device lists yourself** every so often. If
  you don't recognize a script, cron job, or an unfamiliar always-on host
  making frequent API calls to the router, that's worth investigating.
- **A hostname is a hint, not proof — but the MAC vendor prefix (OUI) often
  is.** The first three bytes of a MAC address identify the manufacturer.
  During testing, this tool surfaced an unrecognized host announcing itself
  as `kali` with a MAC starting `00:0c:29` — that prefix is registered to
  VMware, meaning it wasn't a mystery physical device at all, but a *virtual
  machine* with bridged networking running somewhere on the LAN. Look up
  unfamiliar OUIs (e.g. `macvendors.com`) before assuming a strange hostname
  is harmless, or panicking that it's a dedicated physical intruder box.

Finally: **monitoring another person's device presence or behavior without
their knowledge or consent can be illegal** (stalking, harassment, or
computer-misuse statutes, depending on jurisdiction), independent of whether
it's also a violation of trust. This project is published for awareness and
defense, not as a how-to for tracking someone without their consent.

### Zyxel client

`presence_scanner/zyxel_client.py` is a self-contained, `uv`-runnable client for
the Zyxel EX5601-T1. It implements the router's RSA+AES login handshake and
exposes `lan_hosts()` and `arp_table()`. It can be run standalone for debugging:

```bash
ZYXEL_URL=https://192.168.1.1 ZYXEL_USER=admin ZYXEL_PASS=your-password ./presence_scanner/zyxel_client.py
```

### New device monitor

`presence_scanner/new_device_monitor.py` polls the router's connected-hosts
list and flags any *active* MAC address never recorded before, independent
of the tracked `DEVICES` list -- useful for noticing an unrecognized device
joining the network. Events are logged (`NEW DEVICE CONNECTED: ...`) and
persisted to the `known_devices` table so each MAC is only ever reported
once. Note the "never seen before" baseline starts from this monitor's own
records, not the router's full DHCP history, so the very first poll against
a fresh database reports every currently-active device as new.

It runs automatically as a background task alongside the regular scanner
when the app starts (recent events: `GET /api/new-devices`), or standalone:

```bash
uv run presence-watch-new-devices
```

Standalone runs also append events to `new_devices.log` inside `DATA_DIR`.

### Configuration

`presence_scanner/config.py` is the source of truth, and it reads everything
from environment variables -- **no credentials, hostnames, or personal data are
hardcoded in source control**:

- `DEVICES` -- JSON object of tracked devices (name/ip/mac); only track devices
  you have explicit permission to monitor
- `ZYXEL_URL` / `ZYXEL_USER` / `ZYXEL_PASS` -- router `base_url` + credentials
- `HUE_BASE_URL` / `HUE_USERNAME` / `HUE_*_GROUP` / `HUE_ENHANCED_DEVICE_ID` --
  Hue bridge config; leave `HUE_USERNAME` unset to disable Hue entirely
- `NEW_DEVICE_POLL_INTERVAL` -- how often (seconds) to poll for devices never
  seen before; defaults to 30

Copy `.env.example` to `.envrc` (direnv) or `.env`, fill in your own real
values, and never commit that file — it's already git-ignored.

### Requirements

- Python 3.12+
- Network reachability to the router's WAN IP (this host must be whitelisted)

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Full presence status (with enhanced status for the configured device) |
| `/api/scan` | POST | Trigger manual scan |
| `/api/health` | GET | Health check |
| `/api/new-devices` | GET | Recently discovered devices (first-seen, newest first) |

### Deployment

Runs as a systemd service behind nginx, proxied under a `/presence/` path on
your own domain.

```bash
# Service (see systemd/presence-scanner.service)
sudo cp systemd/presence-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now presence-scanner

# Nginx (see nginx/presence.conf)
sudo cp nginx/presence.conf /etc/nginx/sites-available/<your-domain>.d/locations/
sudo nginx -t && sudo systemctl reload nginx
```

The service runs as the `presence` user from `/opt/presence-scanner`, using
`uv run` (deps from `uv.lock`), and stores state in
`/var/lib/presence-scanner/presence.db`.

---

## 2. Security research: CVE-2026-6952

This research builds on the presence scanner above: the router is the
scanner's *source of truth* for who is home, so the post-auth command
injection documented here turns router RCE into a LAN presence-sensor
defeat and home-network takeover.

Lab-validated exploitation chain demonstrating **full router compromise** →
**LAN presence sensor defeat** → **home network takeover**.

### Quick start

```bash
# Clone and enter the repo
git clone https://github.com/whoiscijferslot/presence-scanner
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

### The exploitation chain

```
GET /getRSAPublickKey → RSA+AES login via POST /UserLogin →
read firmware version → if unpatched: inject into LogServer →
command execution as root → full LAN pivot → presence sensor defeat
```

See [`REPORT.md`](REPORT.md) for the complete technical breakdown.

### Lab credentials

The mock and PoC read the **same** two environment variables so they stay in sync:

```bash
export LAB_USER=""   # demo default: admin
export LAB_PASS=""   # demo default: LabPass#2026
```

Precedence: `--user`/`--pass` CLI flags > env > demo defaults. The PoC
**never reads `ZYXEL_PASS`** — the real router password stays scoped to live
targets.

Placeholders: [`poc/.env.example`](poc/.env.example).

### Dependencies

- `uv` (PEP 723 inline script deps) or plain `python3` with packages from
  [`poc/requirements.txt`](poc/requirements.txt)
- Repo root must be importable (run the PoC from the repository root), because
  the PoC imports `presence_scanner`

### Evidence

- Raw evidence: `poc/evidence/pocF_cve_2026_6952_lab_*.jsonl` (git-ignored)
- Sanitized copies: `poc/evidence/pocF_cve_2026_6952_lab_*.public.jsonl`
  (committable, publish-ready)

Generate sanitized copies with the local helper script `sanitize_evidence.py`
(operator-local, intentionally not committed):

```bash
python3 sanitize_evidence.py poc/evidence/pocF_cve_2026_6952_lab_<timestamp>.jsonl <personal-tokens...>
```

### LinkedIn post

[`poc/LINKEDIN_CVE_2026_6952_EXPLOIT_CHAIN.md`](poc/LINKEDIN_CVE_2026_6952_EXPLOIT_CHAIN.md) —
the exploitation-chain walkthrough formatted for social sharing.

### Other proof-of-concepts (archived)

F1–F5 POCs (session replay, slot exhaustion, Hue probe, login storm, WAN
edge) are archived in [`poc/archive/`](poc/archive/) for reference.

---

## License

MIT — for authorized security assessments and research.

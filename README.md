# Presence Scanner

Remote network-presence detection for home automation. The host running this
service is **not** on the home LAN — it reaches the network entirely through two
endpoints exposed on the router's WAN IP, and provides an API for querying
presence status.

## How it works

Two data sources, both remote:

1. **Zyxel router API** (HTTPS, `zyxel_client.py`) — the sole presence source.
   A device counts as present if its MAC is an **active LAN host** or appears in
   the router's **live ARP table**. No ping / ARP / nmap on the host itself
   (it's off-LAN), so this is authoritative.
2. **Philips Hue bridge** (v1 HTTP API, port-forwarded on the router) — enriches
   Roomie's status from room-light state (Downstairs / Around / Awake / Sleeping /
   Away). Optional: if the bridge is unreachable, status degrades gracefully.

Other features:

- **SQLite database** for reliable state persistence
- **Debounced** state changes (a second query confirms appear/disappear)
- **Background scanning** every 60 seconds
- **Web UI** with retro terminal aesthetic

## Zyxel client

`presence_scanner/zyxel_client.py` is a self-contained, `uv`-runnable client for
the Zyxel EX5601-T1. It implements the router's RSA+AES login handshake and
exposes `lan_hosts()` and `arp_table()`. It can be run standalone for debugging:

```bash
ZYXEL_URL=https://203.0.113.1 ./presence_scanner/zyxel_client.py
```

## Configuration

Everything lives in `presence_scanner/config.py` (the source of truth):

- `devices` — tracked MAC addresses (Alex, Roomie)
- `zyxel` — router `base_url`, credentials, timeout
- `hue` — bridge `base_url` (`http://<wan-ip>:25875`), API username, group IDs

`.envrc` mirrors these values for ad-hoc `curl` testing; it is **not** read by
the app.

## Requirements

- Python 3.12+
- Network reachability to the router's WAN IP (this host must be whitelisted)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Full presence status with enhanced Roomie status |
| `/api/roomie-status` | GET | Roomie status only |
| `/api/scan` | POST | Trigger manual scan |
| `/api/health` | GET | Health check |

## Deployment (example.com)

Runs on the server as a systemd service behind nginx at
`https://example.com/presence/`.

```bash
# Service (see systemd/presence-scanner.service)
sudo cp systemd/presence-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now presence-scanner

# Nginx (see nginx/presence.conf)
sudo cp nginx/presence.conf /etc/nginx/sites-available/example.com.d/locations/
sudo nginx -t && sudo systemctl reload nginx
```

The service runs as the `presence` user from `/opt/presence-scanner`, using
`uv run` (deps from `uv.lock`), and stores state in
`/var/lib/presence-scanner/presence.db`.

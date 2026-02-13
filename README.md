# Presence Scanner

Network presence detector for alex-serv. Scans the local network for known MAC addresses and tracks who's home.

## How It Works

1. **`scan.py`** - Runs nmap ping scan every minute (via systemd timer), outputs status to `www/status.json`
2. **`api.py`** - Simple HTTP API on port 5031 to trigger manual scans
3. **`www/`** - Static frontend with hacker-style UI, served via nginx

## Tracked Devices

| ID | Name | MAC |
|----|------|-----|
| alex | Alex | aa:bb:cc:dd:ee:01 |
| roomie | Roomie | aa:bb:cc:dd:ee:02 |

## API

### Status (GET)
```
https://example.com/presence/status.json
```

Response:
```json
{
  "scan_time": "2026-02-13T14:25:18Z",
  "scan_time_human": "2026-02-13 14:25:18 UTC",
  "devices": {
    "alex": {
      "name": "Alex",
      "present": true,
      "last_online": "2026-02-13T14:25:18Z",
      "last_online_human": "2026-02-13 14:25:18 UTC"
    },
    "roomie": {
      "name": "Roomie",
      "present": false,
      "last_online": "2026-02-12T22:15:00Z",
      "last_online_human": "2026-02-12 22:15:00 UTC"
    }
  }
}
```

### Manual Scan (POST)
```
POST https://example.com/presence/api/scan
```

Triggers immediate network scan (debounced to 5s).

## Installation

Files are installed via systemd and nginx:

```bash
# Install systemd services
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now presence-scanner-api.service presence-scanner.timer

# Install nginx config
sudo cp nginx/presence.conf /etc/nginx/sites-available/example.com.d/locations/
sudo nginx -t && sudo systemctl reload nginx
```

## Requirements

- `nmap` for network scanning
- `uv` for Python dependency management
- Root access for nmap (runs as root via systemd)

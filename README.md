# Presence Scanner

Network presence detection for home automation. Detects phones on the local network using nmap and provides an API for querying presence status.

## Features

- **Fast ICMP ping** for primary detection (~2 seconds)
- **ARP/MAC confirmation** for state changes (debounce)
- **SQLite database** for reliable state persistence
- **Hue integration** for enhanced Roomie status (Downstairs/Around/Awake/Sleeping/Away)
- **Background scanning** every 60 seconds
- **Web UI** with retro terminal aesthetic

## Installation

```bash
# Install with uv
uv pip install -e .

# Or run directly
uv run presence-scanner
```

## Requirements

- Python 3.12+
- nmap (must be runnable by the service user)
- SQLite3

### nmap permissions

The service user needs permission to run nmap. Option:

```bash
# Add user to netdev group and configure nmap capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nmap
```

## Configuration

Edit `src/presence_scanner/config.py` to configure:

- `DEVICES`: MAC addresses and IPs to track
- `NETWORK`: Network range for ARP scans
- `SCAN_INTERVAL`: How often to scan (default: 60s)
- `HUE_*`: Philips Hue integration settings

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Full presence status with enhanced Roomie status |
| `/api/roomie-status` | GET | Roomie status only |
| `/api/scan` | POST | Trigger manual scan |
| `/api/health` | GET | Health check |

## Systemd Service

```ini
# /etc/systemd/system/presence-scanner.service
[Unit]
Description=Presence Scanner
After=network.target

[Service]
Type=simple
User=presence
ExecStart=/usr/local/bin/uv run --project /opt/presence-scanner presence-scanner
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Nginx

Copy `nginx/presence.conf` to your nginx config:

```bash
sudo cp nginx/presence.conf /etc/nginx/sites-available/example.com.d/locations/
sudo nginx -t && sudo systemctl reload nginx
```

## Data Storage

Data is stored in `/var/lib/presence-scanner/presence.db`:

- `devices`: Current state for each tracked device
- `scans`: Scan history (auto-pruned to 1000 per device)
- `valou_status`: Enhanced status tracking

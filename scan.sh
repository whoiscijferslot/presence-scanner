#!/bin/bash
# Presence Scanner - Scans network for specific MAC addresses
# Runs as root to detect MAC addresses via ARP

OUTPUT_FILE="/var/www/presence/status.json"
NETWORK="192.168.1.0/24"

# MAC addresses to look for (lowercase for comparison)
SAM_MAC="aa:bb:cc:dd:ee:01"
VALOU_MAC="aa:bb:cc:dd:ee:02"

# Run nmap scan (needs root for MAC detection)
# -sn: Ping scan, no port scan
# -PR: ARP ping (works best on local network)
SCAN_OUTPUT=$(nmap -sn -PR "$NETWORK" 2>/dev/null)

# Get current timestamp
SCAN_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_TIME_HUMAN=$(date +"%Y-%m-%d %H:%M:%S %Z")

# Function to check if MAC is in scan output (case-insensitive)
check_mac() {
    local mac="$1"
    echo "$SCAN_OUTPUT" | grep -i "$mac" > /dev/null
    return $?
}

# Check for each device
if check_mac "$SAM_MAC"; then
    SAM_PRESENT="true"
else
    SAM_PRESENT="false"
fi

if check_mac "$VALOU_MAC"; then
    VALOU_PRESENT="true"
else
    VALOU_PRESENT="false"
fi

# Write JSON output
cat > "$OUTPUT_FILE" << JSONEOF
{
  "scan_time": "$SCAN_TIME",
  "scan_time_human": "$SCAN_TIME_HUMAN",
  "devices": {
    "alex": {
      "name": "Alex",
      "present": $SAM_PRESENT
    },
    "roomie": {
      "name": "Roomie",
      "present": $VALOU_PRESENT
    }
  }
}
JSONEOF

# Set proper permissions so nginx can read it
chmod 644 "$OUTPUT_FILE"

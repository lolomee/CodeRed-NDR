#!/bin/bash
# CodeRed NDR - Rolling PCAP Capture
set -euo pipefail

CONF="/etc/codered/sensor.conf"
PCAP_DIR="/nsm/pcap"
MAX_SIZE_MB=100  # per file
RETENTION_GB=10  # total retention

# Read monitor interface
MON_IF=$(grep -m1 '^monitor_interface' "$CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "")
if [ -z "$MON_IF" ]; then
    MON_IF=$(grep -m1 '^monitor_interfaces' "$CONF" 2>/dev/null | cut -d'=' -f2 | cut -d',' -f1 | tr -d ' ' || echo "")
fi

if [ -z "$MON_IF" ]; then
    echo "No monitor interface configured"
    exit 1
fi

SENSOR_NAME=$(grep -m1 '^sensor_name' "$CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ' || echo "sensor")

mkdir -p "$PCAP_DIR"

exec /usr/bin/tcpdump \
    -i "$MON_IF" \
    -n \
    -w "$PCAP_DIR/${SENSOR_NAME}_%Y%m%d_%H%M%S.pcap" \
    -G 3600 \
    -C "$MAX_SIZE_MB" \
    -z gzip \
    --snapshot-length=0 \
    -Z root

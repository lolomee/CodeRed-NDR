#!/bin/bash
# CodeRed NDR - Suricata start wrapper
set -euo pipefail

CONF="/etc/codered/sensor.conf"
SURICATA_YAML="/etc/suricata/suricata.yaml"
EVE_DIR="/nsm/suricata/log"
PID_FILE="/var/run/suricata.pid"

# Read monitor interface from sensor config
if [ -f "$CONF" ]; then
    MONITOR_IF=$(grep "^monitor_interface" "$CONF" | cut -d'=' -f2 | tr -d ' ')
else
    echo "[!] No sensor.conf found. Run first-boot wizard: sudo /opt/codered/firstboot/firstboot.sh"
    exit 1
fi

if [ -z "$MONITOR_IF" ]; then
    echo "[!] No monitor interface configured."
    exit 1
fi

# Verify interface exists
if ! ip link show "$MONITOR_IF" &>/dev/null; then
    echo "[x] Interface $MONITOR_IF does not exist."
    echo "    Available interfaces:"
    ip -br link show | grep -v lo
    exit 1
fi

# Ensure log directory exists
mkdir -p "$EVE_DIR"

# Prepare interface for capture
ip link set "$MONITOR_IF" up 2>/dev/null || true
ip link set "$MONITOR_IF" promisc on 2>/dev/null || true

# Disable offloading on capture interface (critical for accurate packet capture)
for offload in rx tx sg tso ufo gso gro lro; do
    ethtool -K "$MONITOR_IF" "$offload" off 2>/dev/null || true
done

echo "[+] Starting Suricata on interface: $MONITOR_IF"
exec /usr/bin/suricata \
    -c "$SURICATA_YAML" \
    --af-packet="$MONITOR_IF" \
    --pidfile "$PID_FILE" \
    -D \
    --set "outputs.0.eve-log.filename=$EVE_DIR/eve.json" \
    --set "community-id=true" \
    --set "app-layer.protocols.tls.ja3-fingerprints=yes"

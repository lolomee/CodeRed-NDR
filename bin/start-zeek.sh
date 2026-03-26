#!/bin/bash
# CodeRed NDR - Zeek start wrapper
set -euo pipefail

export PATH="/opt/zeek/bin:$PATH"
CONF="/etc/codered/sensor.conf"

# Read monitor interface from sensor config
if [ -f "$CONF" ]; then
    MONITOR_IF=$(grep "^monitor_interface" "$CONF" | cut -d'=' -f2 | tr -d ' \r\n')
else
    echo "[!] No sensor.conf found. Run first-boot wizard."
    exit 1
fi

if [ -z "$MONITOR_IF" ]; then
    echo "[!] No monitor interface configured."
    exit 1
fi

# Verify interface exists
if ! ip link show "$MONITOR_IF" &>/dev/null; then
    echo "[x] Interface $MONITOR_IF does not exist."
    ip -br link show | grep -v lo
    exit 1
fi

# Update node.cfg with actual interface
sed -i "s|interface=.*|interface=af_packet::${MONITOR_IF}|" /opt/zeek/etc/node.cfg

# Prepare interface
ip link set "$MONITOR_IF" up 2>/dev/null || true
ip link set "$MONITOR_IF" promisc on 2>/dev/null || true
for offload in rx tx sg tso ufo gso gro lro; do
    ethtool -K "$MONITOR_IF" "$offload" off 2>/dev/null || true
done

# Create log dirs
mkdir -p /nsm/zeek/logs/current /nsm/zeek/spool

echo "[+] Starting Zeek on interface: $MONITOR_IF"
/opt/zeek/bin/zeekctl deploy

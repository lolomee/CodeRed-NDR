#!/bin/bash
# CodeRed NDR - Capture Interface Tuning
# Run on every boot for the monitor interface
set -euo pipefail

IFACE="${1:-}"
if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
    echo "[x] Interface $IFACE not found"
    exit 1
fi

echo "[+] Tuning capture interface: $IFACE"

# Bring interface up
ip link set "$IFACE" up

# Enable promiscuous mode
ip link set "$IFACE" promisc on

# Remove any IP addresses (monitor interface should not have an IP)
ip addr flush dev "$IFACE" 2>/dev/null || true

# Disable all offloading — critical for accurate packet capture
# NIC offloading can cause Suricata/Zeek to miss or misparse packets
for offload in rx tx sg tso ufo gso gro lro tx-checksum-ip-generic \
               tx-checksum-ipv4 tx-checksum-ipv6 tx-scatter-gather \
               tx-tcp-segmentation tx-generic-segmentation \
               rx-gro-hw tx-udp_tnl-segmentation; do
    ethtool -K "$IFACE" "$offload" off 2>/dev/null || true
done

# Increase ring buffer to maximum (prevents packet drops at high traffic)
RING_MAX=$(ethtool -g "$IFACE" 2>/dev/null | awk '/Pre-set maximums/,/Current/ {if(/RX:/) print $2}' | head -1)
if [ -n "$RING_MAX" ] && [ "$RING_MAX" -gt 0 ] 2>/dev/null; then
    ethtool -G "$IFACE" rx "$RING_MAX" 2>/dev/null || true
    echo "[+] Ring buffer RX set to max: $RING_MAX"
fi

# Disable pause frames (we never want to slow down the mirror port)
ethtool -A "$IFACE" rx off tx off 2>/dev/null || true

echo "[+] Interface $IFACE tuned for capture"

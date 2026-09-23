#!/bin/bash
# CodeRed NDR — Inline IPS bridge setup / teardown
# Called by codered-inline-ips.service (start/stop) and CLI option 22.
#
# Architecture:
#   [Network A] ──► NIC_A ──► br-ips bridge ──► NIC_B ──► [Network B]
#                                   │
#                              nfqueue q0
#                                   │
#                            Suricata (nfqueue)
#                          DROP / REJECT / ALERT
#
# Fail-open: if Suricata dies or the service stops, the Linux bridge
# keeps forwarding traffic without inspection (safe for the wire).

set -euo pipefail

CONF="/etc/codered/sensor.conf"
LOG_TAG="codered-ips"

log()  { echo "[$(date -Iseconds)] $*"; logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }
err()  { log "ERROR: $*"; exit 1; }
warn() { log "WARN: $*"; }

# ── Read config ────────────────────────────────────────────────
read_conf() {
    local key="$1" default="${2:-}"
    if [ -f "$CONF" ]; then
        val=$(awk -F'=' "/^${key}[[:space:]]*=/{gsub(/^[[:space:]]+|[[:space:]]+$/, \"\", \$2); print \$2; exit}" "$CONF")
        echo "${val:-$default}"
    else
        echo "$default"
    fi
}

IPS_ENABLED=$(read_conf enabled no)
NIC_A=$(read_conf nic_a)
NIC_B=$(read_conf nic_b)
BRIDGE=$(read_conf bridge_name cr-ips-br)
QUEUE=$(read_conf queue_num 0)
FAIL_OPEN=$(read_conf fail_open yes)

# ── Helpers ────────────────────────────────────────────────────
iface_exists() { ip link show "$1" &>/dev/null; }

disable_offloads() {
    local iface="$1"
    for feat in rx tx sg tso ufo gso gro lro; do
        ethtool -K "$iface" "$feat" off 2>/dev/null || true
    done
}

# ── Start ──────────────────────────────────────────────────────
do_start() {
    log "Starting inline IPS mode (bridge=$BRIDGE, NIC_A=$NIC_A, NIC_B=$NIC_B, queue=$QUEUE)"

    [ -n "$NIC_A" ] || err "nic_a not set in sensor.conf — configure via CLI option 22"
    [ -n "$NIC_B" ] || err "nic_b not set in sensor.conf — configure via CLI option 22"
    iface_exists "$NIC_A" || err "NIC_A interface '$NIC_A' does not exist"
    iface_exists "$NIC_B" || err "NIC_B interface '$NIC_B' does not exist"
    [ "$NIC_A" != "$NIC_B" ] || err "NIC_A and NIC_B must be different interfaces"

    # ── Create bridge ──
    if ! iface_exists "$BRIDGE"; then
        ip link add name "$BRIDGE" type bridge
        log "Bridge $BRIDGE created"
    fi

    # Bridge: enable STP off for bump-in-wire (no hello delay)
    ip link set "$BRIDGE" type bridge stp_state 0

    # Bring NICs up, zero any IP, add to bridge
    for NIC in "$NIC_A" "$NIC_B"; do
        ip addr flush dev "$NIC" 2>/dev/null || true
        ip link set "$NIC" up
        ip link set "$NIC" master "$BRIDGE" 2>/dev/null || true
        disable_offloads "$NIC"
        log "  $NIC → bridge $BRIDGE"
    done

    ip link set "$BRIDGE" up
    log "Bridge $BRIDGE up"

    # ── nftables: redirect FORWARD traffic to nfqueue ──
    # We use a dedicated table so we can flush it cleanly on stop.
    nft delete table bridge codered_ips 2>/dev/null || true
    nft add table bridge codered_ips
    nft add chain bridge codered_ips forward '{ type filter hook forward priority 0; policy accept; }'
    nft add rule  bridge codered_ips forward counter queue num "$QUEUE" bypass
    log "nftables: FORWARD → nfqueue $QUEUE (bypass=fail-open)"

    log "Inline IPS bridge ready. Suricata nfqueue will intercept on queue $QUEUE."
}

# ── Stop ───────────────────────────────────────────────────────
do_stop() {
    log "Stopping inline IPS mode"

    # Remove nftables rules first — traffic passes through bridge uninspected
    nft delete table bridge codered_ips 2>/dev/null || true
    log "nftables rules removed (fail-open: traffic passing)"

    # Detach NICs from bridge
    for NIC in "$NIC_A" "$NIC_B"; do
        if [ -n "$NIC" ] && iface_exists "$NIC"; then
            ip link set "$NIC" nomaster 2>/dev/null || true
        fi
    done

    # Delete bridge
    if iface_exists "$BRIDGE"; then
        ip link set "$BRIDGE" down 2>/dev/null || true
        ip link delete "$BRIDGE" type bridge 2>/dev/null || true
        log "Bridge $BRIDGE removed"
    fi

    log "Inline IPS stopped."
}

# ── Status ─────────────────────────────────────────────────────
do_status() {
    echo "=== Inline IPS Status ==="
    echo "  Enabled:     $IPS_ENABLED"
    echo "  NIC-A:       ${NIC_A:-not set}"
    echo "  NIC-B:       ${NIC_B:-not set}"
    echo "  Bridge:      $BRIDGE"
    echo "  Queue:       $QUEUE"
    echo "  Fail-open:   $FAIL_OPEN"
    echo ""

    if iface_exists "$BRIDGE"; then
        echo "  Bridge state: UP"
        ip link show "$BRIDGE" | grep -E 'state|master' || true
        ip link show master "$BRIDGE" 2>/dev/null | grep -E "^[0-9]" | awk '{print "    member: "$2}' || true
    else
        echo "  Bridge state: DOWN (not active)"
    fi
    echo ""

    # nftables
    if nft list table bridge codered_ips &>/dev/null 2>&1; then
        echo "  nfqueue rule: ACTIVE (queue $QUEUE)"
    else
        echo "  nfqueue rule: not loaded"
    fi
    echo ""

    # Suricata nfqueue process
    if pgrep -f "suricata.*-q $QUEUE" >/dev/null 2>&1; then
        echo "  Suricata:    running in nfqueue mode"
    elif systemctl is-active --quiet suricata 2>/dev/null; then
        echo "  Suricata:    running (check mode — may be af-packet not nfqueue)"
    else
        echo "  Suricata:    not running"
    fi
}

# ── Entry ──────────────────────────────────────────────────────
case "${1:-}" in
    start)  do_start  ;;
    stop)   do_stop   ;;
    status) do_status ;;
    restart) do_stop; sleep 1; do_start ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

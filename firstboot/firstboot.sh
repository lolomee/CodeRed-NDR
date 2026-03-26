#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CodeRed NDR - First Boot Setup Wizard                      ║
# ║  Configures sensor on initial deployment                     ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONF="/etc/codered/sensor.conf"
DEFAULTS="/etc/codered/codered.defaults"
MARKER="/var/lib/codered/.firstboot-complete"

[ "$(id -u)" -eq 0 ] || { echo "Must run as root."; exit 1; }

log()  { echo -e "  ${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC}   $*"; }
err()  { echo -e "  ${RED}[x]${NC}   $*"; }
step() { echo -e "\n  ${CYAN}${BOLD}[$1/$TOTAL_STEPS] $2${NC}"; }

TOTAL_STEPS=7

clear
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         CodeRed NDR - First Boot Setup Wizard           ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# ─── Pre-flight: show what we already know ──────────────────
DETECTED_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev")print $(i+1)}' | head -1)
DETECTED_IP=$(ip -4 addr show "$DETECTED_IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)

echo "  Auto-detected:"
echo "    Management interface : ${DETECTED_IFACE:-unknown}"
echo "    Current IP           : ${DETECTED_IP:-DHCP / no IP yet}"
echo ""
echo "  Tip: Press Enter to accept [defaults] shown in brackets."
echo "  Type Ctrl+C at any time to cancel without making changes."
echo ""

# ─── Step 1: Identity ───────────────────────────────────────
step 1 "Sensor identity"

read -rp "  Sensor hostname [codered-sensor]: " INPUT_HOSTNAME
SENSOR_HOSTNAME="${INPUT_HOSTNAME:-codered-sensor}"

read -rp "  Sensor name for SIEM alerts [sensor-01]: " INPUT_SNAME
SENSOR_NAME="${INPUT_SNAME:-sensor-01}"

# ─── Step 2: Management network ─────────────────────────────
step 2 "Management network (NIC 1)"

echo ""
echo "  Available interfaces:"
echo "  ──────────────────────────────────────────────"
ip -br link show | grep -v lo | while read -r iface state mac rest; do
    ADDR=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -1)
    printf "    %-15s  %-8s  %s\n" "$iface" "$state" "${ADDR:-no IP}"
done
echo ""

read -rp "  Management interface [$DETECTED_IFACE]: " INPUT_MGMT
MGMT_IF="${INPUT_MGMT:-$DETECTED_IFACE}"

if ! ip link show "$MGMT_IF" &>/dev/null; then
    err "Interface $MGMT_IF not found."
    exit 1
fi

echo ""
echo "  IP configuration:"
echo "    [1] DHCP (current IP: ${DETECTED_IP:-none})"
echo "    [2] Static IP"
read -rp "  Select [1]: " IP_MODE
IP_MODE="${IP_MODE:-1}"

MGMT_MODE="dhcp"
MGMT_IP=""
MGMT_GATEWAY=""
MGMT_DNS="8.8.8.8,8.8.4.4"

if [ "$IP_MODE" = "2" ]; then
    MGMT_MODE="static"
    read -rp "  Static IP (CIDR, e.g. 192.168.1.100/24): " MGMT_IP
    read -rp "  Gateway: " MGMT_GATEWAY
    read -rp "  DNS servers [8.8.8.8,8.8.4.4]: " INPUT_DNS
    MGMT_DNS="${INPUT_DNS:-8.8.8.8,8.8.4.4}"

    # ── Test gateway reachability before committing ──
    echo ""
    echo "  Testing gateway reachability..."
    if ping -c 2 -W 3 "$MGMT_GATEWAY" &>/dev/null; then
        log "Gateway $MGMT_GATEWAY is reachable."
    else
        warn "Gateway $MGMT_GATEWAY did not respond to ping."
        warn "This may be normal if ICMP is blocked, but double-check your IP/gateway."
        read -rp "  Continue anyway? (Y/n): " GW_CONTINUE
        [[ "${GW_CONTINUE:-Y}" =~ ^[Nn]$ ]] && { echo "  Cancelled."; exit 0; }
    fi
fi

# ─── Step 3: Monitor interface ──────────────────────────────
step 3 "Monitor interface (NIC 2 — SPAN/TAP port)"

AVAILABLE_IFACES=()
while read -r iface; do
    [[ "$iface" != "$MGMT_IF" ]] && AVAILABLE_IFACES+=("$iface")
done < <(ip -br link show | grep -v lo | awk '{print $1}')

echo ""
if [ "${#AVAILABLE_IFACES[@]}" -gt 0 ]; then
    echo "  Available interfaces (excluding management):"
    for i in "${!AVAILABLE_IFACES[@]}"; do
        iface="${AVAILABLE_IFACES[$i]}"
        state=$(ip -br link show "$iface" 2>/dev/null | awk '{print $2}')
        printf "    %d. %-15s  %s\n" "$((i+1))" "$iface" "$state"
    done
    echo ""
fi
echo "  Leave blank to skip — configure later via CLI menu option 7."
read -rp "  Monitor interface (SPAN/TAP): " INPUT_MONITOR

MONITOR_IF=""
if [ -n "$INPUT_MONITOR" ]; then
    # Accept number or name
    if [[ "$INPUT_MONITOR" =~ ^[0-9]+$ ]]; then
        IDX=$((INPUT_MONITOR - 1))
        MONITOR_IF="${AVAILABLE_IFACES[$IDX]:-}"
    else
        MONITOR_IF="$INPUT_MONITOR"
    fi

    if [ -n "$MONITOR_IF" ] && ! ip link show "$MONITOR_IF" &>/dev/null; then
        err "Interface $MONITOR_IF not found."
        exit 1
    fi

    # ── Live SPAN traffic check ──────────────────────
    if [ -n "$MONITOR_IF" ] && command -v tcpdump &>/dev/null; then
        echo ""
        echo "  Checking for traffic on $MONITOR_IF (5 seconds)..."
        echo "  (If your SPAN port is not yet configured, press Ctrl+C and skip)"
        echo ""
        PKTS=0
        if timeout 5 tcpdump -i "$MONITOR_IF" -q --immediate-mode -c 20 2>/dev/null | head -5 | grep -q "IP\|ARP\|VLAN"; then
            PKTS=1
        fi
        # Simpler: just count packets seen
        PKTS=$(timeout 5 tcpdump -i "$MONITOR_IF" -q 2>/dev/null | wc -l || echo 0)
        if [ "${PKTS:-0}" -gt 2 ]; then
            log "Traffic detected on $MONITOR_IF — SPAN port is working!"
        else
            warn "No traffic seen on $MONITOR_IF in 5 seconds."
            warn "Make sure your switch SPAN/mirror port is configured and sending traffic."
            warn "You can still continue — sensor will monitor once SPAN is active."
        fi
    fi
fi

# ─── Step 4: Deployment mode ─────────────────────────────────
step 4 "Deployment mode"

echo ""
echo "  Where is this sensor receiving mirrored traffic from?"
echo ""
echo "    [1] On-premises  Physical/virtual switch SPAN port (default)"
echo "    [2] Cloud        AWS VPC Traffic Mirroring, Alibaba Cloud, Azure vTAP"
echo "                     Traffic arrives VXLAN-encapsulated on UDP/4789"
echo ""
read -rp "  Select [1]: " DEPLOY_MODE
DEPLOY_MODE="${DEPLOY_MODE:-1}"

CLOUD_MODE="no"
VXLAN_PORT="4789"

if [ "$DEPLOY_MODE" = "2" ]; then
    CLOUD_MODE="yes"
    read -rp "  VXLAN port [4789]: " INPUT_VXLAN
    VXLAN_PORT="${INPUT_VXLAN:-4789}"
    echo ""
    warn "Cloud mode enabled. Your security group / firewall must allow:"
    warn "  Inbound UDP/${VXLAN_PORT} from your traffic mirror source ENIs"
    warn "  Without this, mirrored packets will be silently dropped by the VPC."
else
    log "On-premises mode — raw SPAN/TAP capture, no encapsulation."
fi

# ─── Step 5: SIEM forwarding ─────────────────────────────────
step 5 "SIEM log forwarding"

echo ""
echo "  SIEM output type:"
echo "    [1] Elasticsearch  (default port 9200)"
echo "    [2] Logstash       (default port 5044)"
echo "    [3] Syslog / CEF   (default port 514)"
echo "    [4] Skip — configure later"
echo ""
read -rp "  Select [1]: " SIEM_TYPE
SIEM_TYPE="${SIEM_TYPE:-1}"

case "$SIEM_TYPE" in
    1) SIEM_OUTPUT="elasticsearch"; DEFAULT_PORT="9200" ;;
    2) SIEM_OUTPUT="logstash";      DEFAULT_PORT="5044" ;;
    3) SIEM_OUTPUT="syslog";        DEFAULT_PORT="514"  ;;
    4) SIEM_OUTPUT="none";          DEFAULT_PORT=""      ;;
    *) SIEM_OUTPUT="elasticsearch"; DEFAULT_PORT="9200" ;;
esac

SIEM_HOST=""
SIEM_PORT="$DEFAULT_PORT"
SIEM_TLS="false"

if [ "$SIEM_OUTPUT" != "none" ]; then
    read -rp "  SIEM address (IP or FQDN): " SIEM_HOST
    if [ -n "$SIEM_HOST" ]; then
        read -rp "  SIEM port [$DEFAULT_PORT]: " INPUT_PORT
        SIEM_PORT="${INPUT_PORT:-$DEFAULT_PORT}"

        read -rp "  Use TLS? (y/N): " TLS_INPUT
        [[ "${TLS_INPUT:-N}" =~ ^[Yy]$ ]] && SIEM_TLS="true"

        # ── Test SIEM connectivity before saving ─────────
        echo ""
        echo "  Testing SIEM connectivity to $SIEM_HOST:$SIEM_PORT ..."
        if nc -z -w 5 "$SIEM_HOST" "$SIEM_PORT" 2>/dev/null; then
            log "SIEM $SIEM_HOST:$SIEM_PORT is reachable."
        else
            warn "Cannot reach $SIEM_HOST:$SIEM_PORT."
            warn "Check that the SIEM is running and your firewall allows this connection."
            read -rp "  Continue anyway? (Y/n): " SIEM_CONTINUE
            [[ "${SIEM_CONTINUE:-Y}" =~ ^[Nn]$ ]] && { echo "  Cancelled."; exit 0; }
        fi
    else
        warn "No SIEM address set — alerts will not be forwarded until configured."
        warn "Configure later via CLI menu option 8."
    fi
fi

# ─── Step 5: Review and confirm ─────────────────────────────
step 6 "Review configuration"

echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
printf "  │  %-20s %-32s│\n" "Hostname:" "$SENSOR_HOSTNAME"
printf "  │  %-20s %-32s│\n" "Sensor name:" "$SENSOR_NAME"
printf "  │  %-20s %-32s│\n" "Mgmt interface:" "$MGMT_IF ($MGMT_MODE)"
[ "$MGMT_MODE" = "static" ] && printf "  │  %-20s %-32s│\n" "Static IP:" "$MGMT_IP"
printf "  │  %-20s %-32s│\n" "Monitor interface:" "${MONITOR_IF:-not configured}"
printf "  │  %-20s %-32s│\n" "SIEM output:" "$SIEM_OUTPUT"
[ -n "$SIEM_HOST" ] && printf "  │  %-20s %-32s│\n" "SIEM address:" "$SIEM_HOST:$SIEM_PORT (TLS=$SIEM_TLS)"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
read -rp "  Apply this configuration? (Y/n): " CONFIRM
[[ "${CONFIRM:-Y}" =~ ^[Nn]$ ]] && { echo "  Cancelled."; exit 0; }

# ─── Step 6: Apply ──────────────────────────────────────────
step 7 "Applying configuration"

echo ""

# [1/7] Write sensor.conf
echo "  [1/7] Saving configuration..."
cat > "$CONF" << SENSORCONF
# CodeRed NDR - Sensor Configuration
# Generated by first-boot wizard on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[sensor]
hostname = $SENSOR_HOSTNAME
sensor_name = $SENSOR_NAME

[network]
mgmt_interface = $MGMT_IF
mgmt_mode = $MGMT_MODE
mgmt_ip = $MGMT_IP
mgmt_gateway = $MGMT_GATEWAY
mgmt_dns = $MGMT_DNS
monitor_interface = ${MONITOR_IF:-}
cloud_mode = $CLOUD_MODE
vxlan_port = $VXLAN_PORT

[forwarding]
siem_output = $SIEM_OUTPUT
siem_host = ${SIEM_HOST:-}
siem_port = ${SIEM_PORT:-9200}
siem_tls = $SIEM_TLS
SENSORCONF
chmod 640 "$CONF"
log "Configuration saved to $CONF"

# [2/7] Hostname
echo "  [2/7] Setting hostname..."
hostnamectl set-hostname "$SENSOR_HOSTNAME" 2>/dev/null || echo "$SENSOR_HOSTNAME" > /etc/hostname
log "Hostname set to $SENSOR_HOSTNAME"

# [3/7] Zeek salt (safe: check if placeholder still exists before replacing)
echo "  [3/7] Generating Zeek digest salt..."
LOCAL_ZEEK="/opt/zeek/share/zeek/site/local.zeek"
if grep -q "codered-ndr-changeme-at-firstboot" "$LOCAL_ZEEK" 2>/dev/null; then
    ZEEK_SALT=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
    sed -i "s|codered-ndr-changeme-at-firstboot|${ZEEK_SALT}|" "$LOCAL_ZEEK"
    log "Zeek digest salt randomised"
else
    log "Zeek digest salt already set — skipping"
fi

# [4/7] Monitor interface
if [ -n "${MONITOR_IF:-}" ]; then
    echo "  [4/7] Configuring monitor interface $MONITOR_IF..."
    ip link set "$MONITOR_IF" up promisc on 2>/dev/null || true
    ip addr flush dev "$MONITOR_IF" 2>/dev/null || true
    for feat in rx tx sg tso gso gro lro; do
        ethtool -K "$MONITOR_IF" "$feat" off 2>/dev/null || true
    done
    sed -i "s|interface=.*|interface=af_packet::${MONITOR_IF}|" /opt/zeek/etc/node.cfg 2>/dev/null || true
    log "Monitor interface $MONITOR_IF configured (promiscuous, offloads disabled)"
else
    echo "  [4/7] Skipping monitor interface (not configured)..."
fi

# [5/7] SIEM / Filebeat
echo "  [5/7] Configuring log forwarding..."
FILEBEAT_CFG="/etc/filebeat/filebeat.yml"
if [ -n "${SIEM_HOST:-}" ]; then
    sed -i "s|__SIEM_HOST__|${SIEM_HOST}|g" "$FILEBEAT_CFG" 2>/dev/null || true
    sed -i "s|__SIEM_PORT__|${SIEM_PORT}|g" "$FILEBEAT_CFG" 2>/dev/null || true
    log "Filebeat output configured: $SIEM_OUTPUT → $SIEM_HOST:$SIEM_PORT"
else
    log "Filebeat: no SIEM configured — skipping"
fi

# [6/7] Static IP (apply last so SSH stays up during wizard)
if [ "$MGMT_MODE" = "static" ] && [ -n "$MGMT_IP" ]; then
    echo "  [6/7] Applying static IP (connection will briefly drop)..."
    warn "SSH session may disconnect. Reconnect to $MGMT_IP after a few seconds."
    NETPLAN_FILE="/etc/netplan/01-codered-mgmt.yaml"
    cat > "$NETPLAN_FILE" << NETPLAN
network:
  version: 2
  ethernets:
    ${MGMT_IF}:
      addresses:
        - ${MGMT_IP}
      routes:
        - to: default
          via: ${MGMT_GATEWAY}
      nameservers:
        addresses: [$(echo "$MGMT_DNS" | tr ',' ', ')]
NETPLAN
    chmod 600 "$NETPLAN_FILE"
    netplan apply 2>/dev/null || warn "Netplan apply failed — check config manually"
    log "Static IP applied: $MGMT_IP"
else
    echo "  [6/7] DHCP — no IP change needed."
fi

# [7/7] Start services if monitor interface is configured
echo "  [7/7] Starting NDR services..."
if [ -n "${MONITOR_IF:-}" ]; then
    mkdir -p /nsm/zeek/logs/current /nsm/zeek/spool /nsm/suricata/log /var/log/codered
    for svc in codered-zeek codered-suricata filebeat; do
        systemctl enable "$svc" &>/dev/null || true
        systemctl restart "$svc" &>/dev/null || true
    done
    # Brief wait then check
    sleep 3
    ALL_OK=true
    for svc in codered-zeek codered-suricata filebeat; do
        if systemctl is-active "$svc" &>/dev/null; then
            log "$svc: RUNNING"
        else
            warn "$svc: failed to start — check: journalctl -u $svc"
            ALL_OK=false
        fi
    done
    # Update rules in background
    nohup /opt/codered/bin/update-rules.sh &>/var/log/codered/rule-update.log &
    log "Rule update started in background"
else
    # Start Filebeat only (if SIEM configured)
    [ -n "${SIEM_HOST:-}" ] && systemctl enable filebeat &>/dev/null && systemctl restart filebeat &>/dev/null || true
    warn "Zeek and Suricata not started — no monitor interface configured."
    warn "Add a SPAN interface via CLI menu option 7 to begin monitoring."
fi

# Mark complete
mkdir -p /var/lib/codered
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$MARKER"

# ─── Done ───────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${GREEN}${BOLD}║   Setup complete — CodeRed NDR is active                 ║${NC}"
echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -n "${MONITOR_IF:-}" ]; then
    echo "  The sensor is now monitoring traffic. Alerts flow to your SIEM."
    echo ""
    echo "  To verify everything is working:"
    echo "    coderedndr → option 4  (diagnostics)"
    echo "    coderedndr → option 3  (view Zeek/Suricata logs)"
else
    echo "  Partial setup complete. To start monitoring:"
    echo "    1. Configure your switch SPAN port"
    echo "    2. SSH back in: coderedndr → option 7 (add monitor interface)"
fi

echo ""
echo "  Run health check anytime:  sudo /opt/codered/bin/health-check.sh"
echo ""


RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

CONF="/etc/codered/sensor.conf"
DEFAULTS="/etc/codered/codered.defaults"
MARKER="/var/lib/codered/.firstboot-complete"

[ "$(id -u)" -eq 0 ] || { echo "Must run as root."; exit 1; }

clear
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         CodeRed NDR - First Boot Setup Wizard           ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# --- Hostname ---
read -rp "  Sensor hostname [codered-sensor]: " INPUT_HOSTNAME
SENSOR_HOSTNAME="${INPUT_HOSTNAME:-codered-sensor}"

# --- Sensor name ---
read -rp "  Sensor name (identifier for SIEM) [sensor-01]: " INPUT_SNAME
SENSOR_NAME="${INPUT_SNAME:-sensor-01}"

# --- List available interfaces ---
echo ""
echo -e "  ${BOLD}Available network interfaces:${NC}"
echo "  ─────────────────────────────────────"
ip -br link show | grep -v lo | while read -r iface state mac rest; do
    ADDR=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -1)
    printf "    %-15s  %-8s  %s  %s\n" "$iface" "$state" "$mac" "${ADDR:-no-ip}"
done
echo ""

# --- Management interface ---
DEFAULT_MGMT=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev")print $(i+1)}' | head -1)
read -rp "  Management interface [$DEFAULT_MGMT]: " INPUT_MGMT
MGMT_IF="${INPUT_MGMT:-$DEFAULT_MGMT}"

# Validate management interface
if ! ip link show "$MGMT_IF" &>/dev/null; then
    echo -e "  ${RED}[x] Interface $MGMT_IF not found.${NC}"
    exit 1
fi

# --- Management IP config ---
echo ""
echo "  Management IP configuration:"
echo "    [1] DHCP (default)"
echo "    [2] Static IP"
read -rp "  Select [1]: " IP_MODE
IP_MODE="${IP_MODE:-1}"

MGMT_MODE="dhcp"
MGMT_IP=""
MGMT_NETMASK=""
MGMT_GATEWAY=""
MGMT_DNS="8.8.8.8,8.8.4.4"

if [ "$IP_MODE" = "2" ]; then
    MGMT_MODE="static"
    read -rp "  Static IP (CIDR, e.g. 192.168.1.100/24): " MGMT_IP
    read -rp "  Gateway: " MGMT_GATEWAY
    read -rp "  DNS servers [8.8.8.8,8.8.4.4]: " INPUT_DNS
    MGMT_DNS="${INPUT_DNS:-8.8.8.8,8.8.4.4}"
fi

# --- Monitor interface ---
echo ""
read -rp "  Monitor/capture interface (SPAN/TAP port): " MONITOR_IF

if [ -z "$MONITOR_IF" ]; then
    echo -e "  ${YELLOW}[!] No monitor interface set. You can configure this later via CLI.${NC}"
elif ! ip link show "$MONITOR_IF" &>/dev/null; then
    echo -e "  ${RED}[x] Interface $MONITOR_IF not found.${NC}"
    exit 1
fi

# --- SIEM Configuration ---
echo ""
echo -e "  ${BOLD}SIEM Forwarding Configuration:${NC}"
echo "  ─────────────────────────────────────"
echo "    [1] Elasticsearch (default port 9200)"
echo "    [2] Logstash (default port 5044)"
echo "    [3] Syslog / CEF (default port 514)"
echo ""
read -rp "  SIEM output type [1]: " SIEM_TYPE
SIEM_TYPE="${SIEM_TYPE:-1}"

case "$SIEM_TYPE" in
    1) SIEM_OUTPUT="elasticsearch"; DEFAULT_PORT="9200" ;;
    2) SIEM_OUTPUT="logstash"; DEFAULT_PORT="5044" ;;
    3) SIEM_OUTPUT="syslog"; DEFAULT_PORT="514" ;;
    *) SIEM_OUTPUT="elasticsearch"; DEFAULT_PORT="9200" ;;
esac

read -rp "  SIEM address (IP or FQDN): " SIEM_HOST
if [ -z "$SIEM_HOST" ]; then
    echo -e "  ${YELLOW}[!] No SIEM address set. Configure later via CLI.${NC}"
    SIEM_HOST="__SIEM_HOST__"
    SIEM_PORT="$DEFAULT_PORT"
else
    read -rp "  SIEM port [$DEFAULT_PORT]: " INPUT_PORT
    SIEM_PORT="${INPUT_PORT:-$DEFAULT_PORT}"
fi

# TLS
SIEM_TLS="false"
if [ "$SIEM_HOST" != "__SIEM_HOST__" ]; then
    read -rp "  Use TLS for SIEM connection? (y/N): " TLS_INPUT
    if [[ "$TLS_INPUT" =~ ^[Yy]$ ]]; then
        SIEM_TLS="true"
    fi
fi

# --- Summary ---
echo ""
echo -e "  ${BOLD}Configuration Summary:${NC}"
echo "  ─────────────────────────────────────"
echo "  Hostname:           $SENSOR_HOSTNAME"
echo "  Sensor Name:        $SENSOR_NAME"
echo "  Management IF:      $MGMT_IF ($MGMT_MODE)"
[ "$MGMT_MODE" = "static" ] && echo "  Management IP:      $MGMT_IP"
echo "  Monitor IF:         ${MONITOR_IF:-not set}"
echo "  SIEM Output:        $SIEM_OUTPUT"
echo "  SIEM Destination:   $SIEM_HOST:$SIEM_PORT"
echo "  TLS:                $SIEM_TLS"
echo ""
read -rp "  Apply this configuration? (Y/n): " CONFIRM
if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
    echo "  Cancelled."
    exit 0
fi

# --- Apply Configuration ---
echo ""
echo -e "  ${GREEN}Applying configuration...${NC}"

# Write sensor.conf
cat > "$CONF" << SENSORCONF
# CodeRed NDR - Sensor Configuration
# Generated by first-boot wizard on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[sensor]
hostname = $SENSOR_HOSTNAME
sensor_name = $SENSOR_NAME

[network]
mgmt_interface = $MGMT_IF
mgmt_mode = $MGMT_MODE
mgmt_ip = $MGMT_IP
mgmt_gateway = $MGMT_GATEWAY
mgmt_dns = $MGMT_DNS
monitor_interface = ${MONITOR_IF:-}

[forwarding]
siem_output = $SIEM_OUTPUT
siem_host = $SIEM_HOST
siem_port = $SIEM_PORT
siem_tls = $SIEM_TLS
SENSORCONF
chmod 640 "$CONF"

# Set hostname
hostnamectl set-hostname "$SENSOR_HOSTNAME" 2>/dev/null || \
    echo "$SENSOR_HOSTNAME" > /etc/hostname

# Generate unique digest salt for Zeek
ZEEK_SALT=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
sed -i "s|codered-ndr-changeme-at-firstboot|${ZEEK_SALT}|" /opt/zeek/share/zeek/site/local.zeek

# Update Zeek node.cfg with monitor interface
if [ -n "${MONITOR_IF:-}" ]; then
    sed -i "s|interface=.*|interface=af_packet::${MONITOR_IF}|" /opt/zeek/etc/node.cfg

    # Tune the capture interface
    /opt/codered/bin/tune-interface.sh "$MONITOR_IF" 2>/dev/null || true
fi

# Configure Filebeat output
FILEBEAT_CFG="/etc/filebeat/filebeat.yml"

# Disable all outputs first
sed -i 's/^output\.elasticsearch:/output.elasticsearch:/' "$FILEBEAT_CFG"
sed -i 's/^output\.logstash:/output.logstash:/' "$FILEBEAT_CFG"

case "$SIEM_OUTPUT" in
    elasticsearch)
        sed -i "s|__SIEM_HOST__|${SIEM_HOST}|g" "$FILEBEAT_CFG"
        sed -i "s|__SIEM_PORT__|${SIEM_PORT}|g" "$FILEBEAT_CFG"
        # Enable elasticsearch output, disable logstash
        python3 -c "
import re
with open('$FILEBEAT_CFG', 'r') as f:
    content = f.read()
# Enable elasticsearch
content = re.sub(r'(output\.elasticsearch:\n\s+enabled: )false', r'\1true', content)
# Ensure logstash stays disabled
content = re.sub(r'(output\.logstash:\n\s+enabled: )true', r'\1false', content)
# Set TLS
if '$SIEM_TLS' == 'true':
    content = content.replace('protocol: \"https\"', 'protocol: \"https\"')
    content = content.replace('ssl.verification_mode: \"none\"', 'ssl.verification_mode: \"none\"')
else:
    content = content.replace('protocol: \"https\"', 'protocol: \"http\"')
with open('$FILEBEAT_CFG', 'w') as f:
    f.write(content)
"
        ;;
    logstash)
        sed -i "s|__SIEM_HOST__|${SIEM_HOST}|g" "$FILEBEAT_CFG"
        sed -i "s|__SIEM_PORT__|${SIEM_PORT}|g" "$FILEBEAT_CFG"
        python3 -c "
import re
with open('$FILEBEAT_CFG', 'r') as f:
    content = f.read()
content = re.sub(r'(output\.elasticsearch:\n\s+enabled: )true', r'\1false', content)
content = re.sub(r'(output\.logstash:\n\s+enabled: )false', r'\1true', content)
if '$SIEM_TLS' == 'true':
    content = content.replace('ssl.enabled: false', 'ssl.enabled: true')
with open('$FILEBEAT_CFG', 'w') as f:
    f.write(content)
"
        ;;
    syslog)
        # For syslog output, replace the logstash section with syslog
        python3 -c "
import re
with open('$FILEBEAT_CFG', 'r') as f:
    content = f.read()
content = re.sub(r'(output\.elasticsearch:\n\s+enabled: )true', r'\1false', content)
content = re.sub(r'(output\.logstash:\n\s+enabled: )true', r'\1false', content)
# Append syslog output
syslog_cfg = '''
output.syslog:
  enabled: true
  address: \"$SIEM_HOST:$SIEM_PORT\"
  network: \"tcp\"
  format: \"rfc5424\"
'''
content += syslog_cfg
with open('$FILEBEAT_CFG', 'w') as f:
    f.write(content)
"
        ;;
esac

# Set sensor name in Filebeat
sed -i "s|\${SENSOR_NAME:codered-sensor}|\${SENSOR_NAME:${SENSOR_NAME}}|g" "$FILEBEAT_CFG"

# Configure static IP if selected
if [ "$MGMT_MODE" = "static" ] && [ -n "$MGMT_IP" ]; then
    # Use netplan (Ubuntu 24.04 standard)
    NETPLAN_FILE="/etc/netplan/01-codered-mgmt.yaml"
    cat > "$NETPLAN_FILE" << NETPLAN
network:
  version: 2
  ethernets:
    ${MGMT_IF}:
      addresses:
        - ${MGMT_IP}
      routes:
        - to: default
          via: ${MGMT_GATEWAY}
      nameservers:
        addresses: [$(echo "$MGMT_DNS" | tr ',' ', ')]
NETPLAN
    chmod 600 "$NETPLAN_FILE"
    netplan apply 2>/dev/null || warn "Netplan apply failed — check config manually"
fi

# Mark first boot as complete
touch "$MARKER"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$MARKER"

echo ""
echo -e "  ${GREEN}${BOLD}Configuration applied successfully!${NC}"
echo ""
echo "  Next steps:"
echo "    1. Start NDR services:  sudo coderedndr  → option 9"
echo "    2. Verify logs flowing:  sudo coderedndr  → option 3"
echo ""

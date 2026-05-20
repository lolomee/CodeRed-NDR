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

    # ── Live SPAN traffic check (single 5-second run) ─────
    if [ -n "$MONITOR_IF" ] && command -v tcpdump &>/dev/null; then
        echo ""
        echo "  Checking for traffic on $MONITOR_IF (5 seconds)..."
        echo "  (Press Ctrl+C to skip if SPAN is not yet configured)"
        echo ""
        # Single tcpdump run — count lines output in 5 seconds
        PKTS=$(timeout 5 tcpdump -i "$MONITOR_IF" -q --immediate-mode 2>/dev/null | wc -l || echo 0)
        if [ "${PKTS:-0}" -gt 2 ]; then
            log "Traffic detected on $MONITOR_IF (${PKTS} packets) — SPAN port is working!"
        else
            warn "No traffic seen on $MONITOR_IF in 5 seconds."
            warn "Make sure your SPAN/mirror port is configured and sending traffic."
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
echo "    [1] Elasticsearch  (HTTP/HTTPS — Elastic, OpenSearch, Splunk HEC)"
echo "    [2] Logstash       (Beats protocol TCP — Logstash, Wazuh)"
echo "    [3] Syslog TCP     (raw syslog TCP — Pre Security, QRadar, Graylog)"
echo "    [4] Syslog UDP     (raw syslog UDP)"
echo "    [5] Skip — configure later"
echo ""
read -rp "  Select [1]: " SIEM_TYPE
SIEM_TYPE="${SIEM_TYPE:-1}"

case "$SIEM_TYPE" in
    1) SIEM_OUTPUT="elasticsearch"; DEFAULT_PORT="9200" ;;
    2) SIEM_OUTPUT="logstash";      DEFAULT_PORT="5044" ;;
    3) SIEM_OUTPUT="syslog-tcp";    DEFAULT_PORT="514"  ;;
    4) SIEM_OUTPUT="syslog-udp";    DEFAULT_PORT="514"  ;;
    5) SIEM_OUTPUT="none";          DEFAULT_PORT=""      ;;
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

# ─── Step 6: Review and confirm ─────────────────────────────
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
siem_tls_verify = true
siem_tls_ca =
siem_tls_servername =
siem_tls_cert =
siem_tls_key =
siem_proto = ${SIEM_PROTO:-tcp}
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

# [4/7] Monitor interface + cloud mode VXLAN config
if [ -n "${MONITOR_IF:-}" ]; then
    echo "  [4/7] Configuring monitor interface $MONITOR_IF..."
    ip link set "$MONITOR_IF" up promisc on 2>/dev/null || true
    ip addr flush dev "$MONITOR_IF" 2>/dev/null || true
    for feat in rx tx sg tso gso gro lro; do
        ethtool -K "$MONITOR_IF" "$feat" off 2>/dev/null || true
    done
    sed -i "s|interface=.*|interface=af_packet::${MONITOR_IF}|" /opt/zeek/etc/node.cfg 2>/dev/null || true
    log "Monitor interface $MONITOR_IF configured (promiscuous, offloads disabled)"

    # Cloud mode: enable VXLAN decapsulation in Zeek and Suricata
    if [ "${CLOUD_MODE:-no}" = "yes" ]; then
        echo "  [4/7] Applying cloud mode VXLAN decapsulation..."

        # Zeek: uncomment VXLAN redef lines between the cloud mode markers
        if [ -f "$LOCAL_ZEEK" ]; then
            # Enable VXLAN redef lines using awk (avoids all quoting issues)
            awk '/CLOUD_MODE_START/{in_block=1; print; next} /CLOUD_MODE_END/{in_block=0; print; next} in_block && /^# redef/{sub(/^# /,""); print; next} {print}' \
                "$LOCAL_ZEEK" > "${LOCAL_ZEEK}.tmp" 2>/dev/null && \
                mv "${LOCAL_ZEEK}.tmp" "$LOCAL_ZEEK" 2>/dev/null && \
                log "Zeek VXLAN decapsulation enabled" || \
                warn "Could not update local.zeek -- toggle via Menu -> 9"
        fi

        # Suricata: write override config with VXLAN decoder
        SURI_OVERRIDE="/etc/suricata/codered-override.yaml"
        cat > "$SURI_OVERRIDE" << SURICATA_YAML
%YAML 1.1
---
# CodeRed NDR - Suricata Override (cloud mode -- VXLAN decap enabled)
# Auto-generated by first-boot wizard

af-packet:
  - interface: ${MONITOR_IF}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

decoder:
  vxlan:
    enabled: yes
    ports:
      - ${VXLAN_PORT:-4789}

community-id:
  enabled: true

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /nsm/suricata/log/eve.json
      community-id: true
      types:
        - alert:
            tagged-packets: yes
            metadata: yes
        - anomaly:
            enabled: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
            ja3: yes
        - ssh
        - flow
SURICATA_YAML
        chmod 640 "$SURI_OVERRIDE" 2>/dev/null || true
        log "Suricata VXLAN decoder enabled (UDP/${VXLAN_PORT:-4789})"

        # Cloud mode MTU warning — AWS/AliCloud add 50-byte VXLAN overhead
        warn "IMPORTANT: AWS/AliCloud VXLAN adds 50-byte overhead per packet."
        warn "  If monitored instances use MTU 1500, mirrored packets may fragment."
        warn "  Recommended: reduce MTU on monitored instances to 1428 bytes, OR"
        warn "  set MTU 1550+ on this sensor's monitor interface:"
        warn "    ip link set ${MONITOR_IF} mtu 1550"
    fi
else
    echo "  [4/7] Skipping monitor interface (not configured)..."
fi

# [5/7] SIEM / Filebeat — write complete config from scratch
echo "  [5/7] Configuring log forwarding..."
FILEBEAT_CFG="/etc/filebeat/filebeat.yml"

# Determine protocol
FB_PROTOCOL="http"
[ "${SIEM_TLS:-false}" = "true" ] && FB_PROTOCOL="https"

# Write a complete Filebeat config rather than sed-patching the default
# (the default Elastic filebeat.yml has no __SIEM_HOST__ placeholders)
cat > "$FILEBEAT_CFG" << FBEOF
# CodeRed NDR - Filebeat Configuration
# Generated by first-boot wizard on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

name: "${SENSOR_NAME:-sensor-01}"

filebeat.inputs:
  - type: log
    id: zeek-logs
    enabled: true
    paths:
      - /nsm/zeek/logs/current/*.log
    exclude_files: ['.gz\$', 'stderr.log', 'stdout.log', 'capture_loss.log', 'reporter.log', 'stats.log']
    fields:
      source: zeek
      sensor_name: "${SENSOR_NAME:-sensor-01}"
    fields_under_root: false

  - type: log
    id: suricata-eve
    enabled: true
    paths:
      - /nsm/suricata/log/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
    fields:
      source: suricata
      sensor_name: "${SENSOR_NAME:-sensor-01}"
    fields_under_root: false

  - type: log
    id: codered-ml-alerts
    enabled: true
    paths:
      - /nsm/codered/ml-alerts.json
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
    fields:
      source: codered-ml
      log_type: behavioral_anomaly
    fields_under_root: false
    ignore_older: 24h

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: observer
      fields:
        name: "${SENSOR_NAME:-sensor-01}"
        type: ndr
        vendor: CodeRed
        product: CodeRed NDR

FBEOF

# Append SIEM output section
if [ -n "${SIEM_HOST:-}" ]; then
    case "${SIEM_OUTPUT:-elasticsearch}" in
        logstash)
            cat >> "$FILEBEAT_CFG" << LSEOF
output.logstash:
  enabled: true
  hosts: ["${SIEM_HOST}:${SIEM_PORT:-5044}"]
LSEOF
            ;;
        syslog-tcp|syslog-udp)
            # Raw syslog handled by codered-syslog-forwarder.py, not Filebeat
            # Write buffer output so Filebeat stays quiet
            cat >> "$FILEBEAT_CFG" << SLEOF
output.file:
  enabled: true
  path: /var/log/codered
  filename: filebeat-buffer
  rotate_every_kb: 10240
  number_of_files: 3
SLEOF
            ;;
        *)
            cat >> "$FILEBEAT_CFG" << ESEOF
output.elasticsearch:
  enabled: true
  hosts: ["${FB_PROTOCOL}://${SIEM_HOST}:${SIEM_PORT:-9200}"]
ESEOF
            ;;
    esac
    log "Filebeat configured: ${SIEM_OUTPUT:-elasticsearch} -> $SIEM_HOST:${SIEM_PORT}"
else
    cat >> "$FILEBEAT_CFG" << NOEOF
# No SIEM configured — logging to file only until SIEM is set
# Configure via: sudo coderedndr -> option 8
output.file:
  enabled: true
  path: /var/log/codered
  filename: filebeat-buffer
  rotate_every_kb: 10240
  number_of_files: 3
NOEOF
    warn "No SIEM address set — Filebeat output not configured."
    warn "Configure later: sudo coderedndr -> option 8 (SIEM destination)"
fi

# Add logging config
cat >> "$FILEBEAT_CFG" << LOGEOF

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
LOGEOF

chmod 600 "$FILEBEAT_CFG"

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
    mkdir -p /nsm/zeek/logs/current /nsm/zeek/spool /nsm/suricata/log /var/log/codered                /nsm/codered /var/lib/codered
    for svc in codered-zeek codered-suricata filebeat codered-ml; do
        systemctl enable "$svc" &>/dev/null || true
        systemctl restart "$svc" &>/dev/null || true
    done
    # Brief wait then check
    sleep 3
    ALL_OK=true
    for svc in codered-zeek codered-suricata filebeat codered-ml; do
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
    # Start appropriate forwarder based on output type
    if [ -n "${SIEM_HOST:-}" ]; then
        case "${SIEM_OUTPUT:-elasticsearch}" in
            syslog-tcp|syslog-udp)
                # Use native syslog forwarder — Filebeat can't do raw syslog
                systemctl disable filebeat &>/dev/null || true
                systemctl stop filebeat &>/dev/null || true
                systemctl enable codered-syslog &>/dev/null || true
                systemctl restart codered-syslog &>/dev/null || true
                log "Syslog forwarder started -> ${SIEM_OUTPUT} ${SIEM_HOST}:${SIEM_PORT}"
                ;;
            *)
                # Use Filebeat for Elasticsearch/Logstash
                systemctl disable codered-syslog &>/dev/null || true
                systemctl stop codered-syslog &>/dev/null || true
                systemctl enable filebeat &>/dev/null || true
                systemctl restart filebeat &>/dev/null || true
                log "Filebeat started -> ${SIEM_OUTPUT} ${SIEM_HOST}:${SIEM_PORT}"
                ;;
        esac
    fi
    warn "Zeek and Suricata not started — no monitor interface configured."
    warn "Add a SPAN interface via CLI menu option 7 to begin monitoring."
fi

# Mark complete — write BOTH markers:
# 1. .firstboot-complete — checked by firstboot.sh itself on re-run
# 2. .setup-complete     — checked by the CLI (is_configured()) to skip wizard
mkdir -p /var/lib/codered /etc/codered
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$MARKER"
touch /etc/codered/.setup-complete
chmod 644 /etc/codered/.setup-complete

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



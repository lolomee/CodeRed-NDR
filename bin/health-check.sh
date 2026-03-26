#!/bin/bash
# CodeRed NDR - Enhanced Health Check
# Returns: 0=healthy, 1=degraded, 2=critical
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

WARNINGS=0
CRITICALS=0

ok()   { echo -e "  ${GREEN}[OK]${NC}     $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC}   $1"; ((WARNINGS++)); }
crit() { echo -e "  ${RED}[CRIT]${NC}   $1"; ((CRITICALS++)); }

# Load sensor config
CONF_FILE="/etc/codered/sensor.conf"
MON_IF=""
SIEM_HOST=""
SIEM_PORT="9200"
if [ -f "$CONF_FILE" ]; then
    MON_IF=$(grep "^monitor_interface\b" "$CONF_FILE" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
    SIEM_HOST=$(grep "^siem_host" "$CONF_FILE" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
    SIEM_PORT=$(grep "^siem_port" "$CONF_FILE" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
    SIEM_PORT="${SIEM_PORT:-9200}"
fi

echo -e "${BOLD}CodeRed NDR Health Check${NC}"
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "════════════════════════════════════════════════════════"

# ── Configuration ──
echo -e "\n${BOLD}Configuration${NC}"
if [ -f /etc/codered/sensor.conf ]; then
    ok "Sensor configured"
else
    crit "Sensor NOT configured (/etc/codered/sensor.conf missing)"
fi

if [ -f /var/lib/codered/.firstboot-complete ]; then
    ok "First boot complete"
else
    warn "First boot not completed"
fi

# ── Services & Uptime ──
echo -e "\n${BOLD}Services${NC}"
for svc_pair in "codered-zeek:zeek" "codered-suricata:suricata" "filebeat:filebeat" "codered-pcap:codered-pcap"; do
    svc="${svc_pair%%:*}"
    proc="${svc_pair##*:}"
    if systemctl is-active "$svc" &>/dev/null; then
        # Get uptime from systemd
        started=$(systemctl show "$svc" --property=ActiveEnterTimestamp 2>/dev/null | cut -d'=' -f2-)
        if [ -n "$started" ] && [ "$started" != "" ]; then
            started_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            if [ "$started_epoch" -gt 0 ] 2>/dev/null; then
                uptime_secs=$((now_epoch - started_epoch))
                days=$((uptime_secs / 86400))
                hours=$(( (uptime_secs % 86400) / 3600 ))
                mins=$(( (uptime_secs % 3600) / 60 ))
                uptime_str="${days}d ${hours}h ${mins}m"
            else
                uptime_str="unknown"
            fi
        else
            uptime_str="unknown"
        fi
        ok "$svc: RUNNING (uptime: $uptime_str)"
    else
        # codered-pcap is optional, only warn
        if [ "$svc" = "codered-pcap" ]; then
            warn "$svc: not running (optional)"
        else
            crit "$svc: NOT RUNNING"
        fi
    fi
done

# ── Performance Metrics (CPU/Memory per process) ──
echo -e "\n${BOLD}Performance Metrics${NC}"
for proc in zeek suricata filebeat; do
    pid=$(pgrep -x "$proc" 2>/dev/null | head -1)
    if [ -z "$pid" ]; then
        pid=$(pgrep -f "$proc" 2>/dev/null | head -1)
    fi
    if [ -n "$pid" ]; then
        cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
        mem=$(ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' ')
        rss=$(ps -p "$pid" -o rss= 2>/dev/null | tr -d ' ')
        rss_mb=$((rss / 1024))
        echo -e "  ${GREEN}[OK]${NC}     $proc (PID $pid): CPU=${cpu}%  MEM=${mem}% (${rss_mb} MB)"
    else
        echo -e "  ${YELLOW}[----]${NC}   $proc: not running"
    fi
done

# System-wide load
load=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}')
cpus=$(nproc 2>/dev/null || echo 1)
if [ -n "$load" ]; then
    load_int=${load%%.*}
    if [ "$load_int" -ge "$((cpus * 2))" ] 2>/dev/null; then
        warn "System load: $load (${cpus} CPUs) - HIGH"
    else
        ok "System load: $load (${cpus} CPUs)"
    fi
fi

# Memory
mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)
mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null)
if [ -n "$mem_total" ] && [ -n "$mem_avail" ] && [ "$mem_total" -gt 0 ] 2>/dev/null; then
    mem_used_pct=$(( (mem_total - mem_avail) * 100 / mem_total ))
    if [ "$mem_used_pct" -ge 95 ]; then
        crit "Memory usage: ${mem_used_pct}% - CRITICAL"
    elif [ "$mem_used_pct" -ge 85 ]; then
        warn "Memory usage: ${mem_used_pct}%"
    else
        ok "Memory usage: ${mem_used_pct}%"
    fi
fi

# ── Disk Space ──
echo -e "\n${BOLD}Disk Space${NC}"
for mount in / /nsm; do
    if mountpoint -q "$mount" 2>/dev/null || [ "$mount" = "/" ]; then
        usage=$(df "$mount" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')
        size=$(df -h "$mount" 2>/dev/null | awk 'NR==2 {print $2}')
        avail=$(df -h "$mount" 2>/dev/null | awk 'NR==2 {print $4}')
        if [ -n "$usage" ]; then
            if [ "$usage" -ge 95 ]; then
                crit "$mount: ${usage}% used (${avail} free of ${size}) - CRITICAL"
            elif [ "$usage" -ge 85 ]; then
                warn "$mount: ${usage}% used (${avail} free of ${size})"
            elif [ "$usage" -ge 75 ]; then
                warn "$mount: ${usage}% used (${avail} free of ${size}) - getting full"
            else
                ok "$mount: ${usage}% used (${avail} free of ${size})"
            fi
        fi
    fi
done

# ── Packet Loss / Capture Stats ──
echo -e "\n${BOLD}Packet Capture${NC}"

# Monitor interface check
if [ -n "$MON_IF" ]; then
    if ip link show "$MON_IF" 2>/dev/null | grep -q 'PROMISC'; then
        ok "Monitor interface ($MON_IF): UP, PROMISC"
    elif ip link show "$MON_IF" 2>/dev/null | grep -q 'state UP'; then
        warn "Monitor interface ($MON_IF): UP but NOT promiscuous"
    else
        crit "Monitor interface ($MON_IF): DOWN"
    fi
else
    warn "No monitor interface configured"
fi

# Suricata AF_PACKET stats via suricatasc
if command -v suricatasc &>/dev/null && pgrep -x suricata &>/dev/null; then
    iface_stat=$(suricatasc -c "iface-stat $MON_IF" 2>/dev/null)
    if [ -n "$iface_stat" ]; then
        pkts=$(echo "$iface_stat" | grep -oP '"pkts":\s*\K[0-9]+' 2>/dev/null || echo "")
        drops=$(echo "$iface_stat" | grep -oP '"drop":\s*\K[0-9]+' 2>/dev/null || echo "")
        if [ -n "$pkts" ] && [ -n "$drops" ] && [ "$pkts" -gt 0 ] 2>/dev/null; then
            drop_pct=$(( drops * 100 / pkts ))
            if [ "$drop_pct" -ge 5 ]; then
                crit "Suricata AF_PACKET: ${pkts} pkts, ${drops} drops (${drop_pct}%)"
            elif [ "$drop_pct" -ge 1 ]; then
                warn "Suricata AF_PACKET: ${pkts} pkts, ${drops} drops (${drop_pct}%)"
            else
                ok "Suricata AF_PACKET: ${pkts} pkts, ${drops} drops (${drop_pct}%)"
            fi
        elif [ -n "$pkts" ]; then
            ok "Suricata AF_PACKET: ${pkts} pkts received"
        fi
    fi
else
    echo -e "  ${YELLOW}[----]${NC}   Suricata capture stats: unavailable"
fi

# Zeek capture_loss.log
ZEEK_CAPTURE_LOSS="/nsm/zeek/logs/current/capture_loss.log"
if [ -f "$ZEEK_CAPTURE_LOSS" ]; then
    last_loss=$(tail -5 "$ZEEK_CAPTURE_LOSS" 2>/dev/null | grep -v '^#' | tail -1)
    if [ -n "$last_loss" ]; then
        pct_lost=$(echo "$last_loss" | awk '{print $NF}')
        if [ -n "$pct_lost" ] && [ "$pct_lost" != "-" ]; then
            loss_int=${pct_lost%%.*}
            if [ "${loss_int:-0}" -ge 5 ] 2>/dev/null; then
                warn "Zeek capture loss: ${pct_lost}%"
            else
                ok "Zeek capture loss: ${pct_lost}%"
            fi
        else
            ok "Zeek capture_loss.log: no loss recorded"
        fi
    fi
else
    echo -e "  ${YELLOW}[----]${NC}   Zeek capture_loss.log: not found"
fi

# ── Log Generation Rate ──
echo -e "\n${BOLD}Log Generation${NC}"

check_log_freshness() {
    local label="$1" path="$2" max_age_mins="${3:-10}"
    if [ -f "$path" ]; then
        mtime=$(stat -c %Y "$path" 2>/dev/null || echo 0)
        now=$(date +%s)
        age_secs=$((now - mtime))
        age_mins=$((age_secs / 60))
        if [ "$age_mins" -le "$max_age_mins" ]; then
            ok "$label: active (updated ${age_mins}m ago)"
        elif [ "$age_mins" -le 60 ]; then
            warn "$label: stale (last update ${age_mins}m ago)"
        else
            crit "$label: no recent data (${age_mins}m since last write)"
        fi
    else
        crit "$label: file not found"
    fi
}

check_log_freshness "Suricata EVE" "/nsm/suricata/log/eve.json" 10
check_log_freshness "Zeek conn.log" "/nsm/zeek/logs/current/conn.log" 10
check_log_freshness "Zeek dns.log"  "/nsm/zeek/logs/current/dns.log" 10

# ── SIEM Connectivity ──
echo -e "\n${BOLD}SIEM Connectivity${NC}"
if [ -n "$SIEM_HOST" ]; then
    if nc -z -w 5 "$SIEM_HOST" "$SIEM_PORT" 2>/dev/null; then
        ok "SIEM endpoint $SIEM_HOST:$SIEM_PORT: reachable"
    else
        crit "SIEM endpoint $SIEM_HOST:$SIEM_PORT: UNREACHABLE"
    fi

    # Check Filebeat shipping health
    if [ -f /var/log/filebeat/filebeat ]; then
        fb_errors=$(tail -50 /var/log/filebeat/filebeat 2>/dev/null | grep -ci 'error\|failed' || echo 0)
        if [ "$fb_errors" -gt 5 ]; then
            warn "Filebeat recent errors: $fb_errors in last 50 lines"
        else
            ok "Filebeat log: $fb_errors errors in last 50 lines"
        fi
    fi
else
    warn "SIEM endpoint: not configured"
fi

# ── Intel Feed Freshness ──
echo -e "\n${BOLD}Threat Intelligence${NC}"

# Suricata rules
RULES_DIR="/var/lib/suricata/rules"
if [ -d "$RULES_DIR" ] && ls "$RULES_DIR"/*.rules &>/dev/null; then
    newest_rule=$(stat -c %Y "$RULES_DIR"/*.rules 2>/dev/null | sort -rn | head -1)
    if [ -n "$newest_rule" ]; then
        now=$(date +%s)
        age_days=$(( (now - newest_rule) / 86400 ))
        rule_date=$(date -d "@$newest_rule" '+%Y-%m-%d %H:%M' 2>/dev/null)
        if [ "$age_days" -ge 7 ]; then
            warn "Suricata rules: last updated $rule_date (${age_days} days ago)"
        else
            ok "Suricata rules: last updated $rule_date (${age_days} days ago)"
        fi
    fi
else
    crit "Suricata rules: NONE FOUND"
fi

# Zeek intel feeds
INTEL_DIR="/opt/zeek/share/zeek/site/intel"
if [ -d "$INTEL_DIR" ] && ls "$INTEL_DIR"/*.dat &>/dev/null 2>&1; then
    newest_intel=$(stat -c %Y "$INTEL_DIR"/*.dat 2>/dev/null | sort -rn | head -1)
    if [ -n "$newest_intel" ]; then
        now=$(date +%s)
        age_days=$(( (now - newest_intel) / 86400 ))
        intel_date=$(date -d "@$newest_intel" '+%Y-%m-%d %H:%M' 2>/dev/null)
        if [ "$age_days" -ge 7 ]; then
            warn "Zeek intel feeds: last updated $intel_date (${age_days} days ago)"
        else
            ok "Zeek intel feeds: last updated $intel_date (${age_days} days ago)"
        fi
    fi
else
    warn "Zeek intel feeds: no .dat files found"
fi

# ── Other ──
echo -e "\n${BOLD}Other${NC}"
if [ -f /usr/share/GeoIP/GeoLite2-City.mmdb ]; then
    ok "GeoIP database present"
else
    warn "GeoIP database missing"
fi

# NTP
if timedatectl show --property=NTPSynchronized 2>/dev/null | grep -qi 'yes'; then
    ok "NTP synchronized"
else
    warn "NTP NOT synchronized"
fi

# ── Summary ──
echo ""
echo "════════════════════════════════════════════════════════"
TOTAL=$((WARNINGS + CRITICALS))
if [ "$CRITICALS" -gt 0 ]; then
    echo -e "${RED}${BOLD}CRITICAL: ${CRITICALS} critical, ${WARNINGS} warning(s)${NC}"
    exit 2
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}${BOLD}DEGRADED: ${WARNINGS} warning(s)${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}HEALTHY: All checks passed${NC}"
    exit 0
fi

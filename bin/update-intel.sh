#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CodeRed NDR - Threat Intel Feed Updater                    ║
# ║  Downloads abuse.ch feeds and converts to Zeek Intel format ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

INTEL_DIR="/opt/zeek/share/zeek/site/intel"
TMP_DIR=$(mktemp -d)
HEADER="#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"

log()  { echo "[+] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
warn() { echo "[!] $(date '+%Y-%m-%d %H:%M:%S') $*"; }

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

mkdir -p "$INTEL_DIR"

# ─── URLhaus (recent URLs) ───
log "Downloading URLhaus feed..."
if curl -sSL --max-time 120 -o "$TMP_DIR/urlhaus.csv" \
    "https://urlhaus.abuse.ch/downloads/csv_recent/" 2>/dev/null; then
    {
        printf '%b\n' "$HEADER"
        grep -v '^#' "$TMP_DIR/urlhaus.csv" | grep -v '^"id"' | \
        while IFS=',' read -r id dateadded url url_status threat tags urlhaus_link reporter; do
            # Remove surrounding quotes
            url=$(echo "$url" | tr -d '"')
            [ -z "$url" ] && continue
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$url" "Intel::URL" "abuse.ch URLhaus" "Malware distribution URL" \
                "https://urlhaus.abuse.ch"
        done
    } > "$INTEL_DIR/abuse-ch-urlhaus.intel"
    log "URLhaus feed updated: $(wc -l < "$INTEL_DIR/abuse-ch-urlhaus.intel") entries"
else
    warn "URLhaus download failed"
fi

# ─── Feodo Tracker (C2 IPs) ───
log "Downloading Feodo Tracker feed..."
if curl -sSL --max-time 120 -o "$TMP_DIR/feodo.csv" \
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" 2>/dev/null; then
    {
        printf '%b\n' "$HEADER"
        grep -v '^#' "$TMP_DIR/feodo.csv" | grep -v '^"first_seen' | \
        while IFS=',' read -r first_seen dst_ip dst_port last_online malware; do
            ip=$(echo "$dst_ip" | tr -d '"' | xargs)
            [ -z "$ip" ] && continue
            malware_clean=$(echo "$malware" | tr -d '"' | xargs)
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$ip" "Intel::ADDR" "abuse.ch Feodo Tracker" \
                "Botnet C2 ($malware_clean)" \
                "https://feodotracker.abuse.ch"
        done
    } > "$INTEL_DIR/abuse-ch-feodo.intel"
    log "Feodo Tracker feed updated: $(wc -l < "$INTEL_DIR/abuse-ch-feodo.intel") entries"
else
    warn "Feodo Tracker download failed"
fi

# ─── SSL Blacklist (malicious SSL IPs) ───
log "Downloading SSL Blacklist feed..."
if curl -sSL --max-time 120 -o "$TMP_DIR/sslbl.csv" \
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv" 2>/dev/null; then
    {
        printf '%b\n' "$HEADER"
        grep -v '^#' "$TMP_DIR/sslbl.csv" | grep -v '^"first' | \
        while IFS=',' read -r first_seen dst_ip dst_port reason sha1; do
            ip=$(echo "$dst_ip" | tr -d '"' | xargs)
            [ -z "$ip" ] && continue
            reason_clean=$(echo "$reason" | tr -d '"' | xargs)
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$ip" "Intel::ADDR" "abuse.ch SSLBL" \
                "Malicious SSL ($reason_clean)" \
                "https://sslbl.abuse.ch"
        done
    } > "$INTEL_DIR/abuse-ch-sslbl.intel"
    log "SSL Blacklist feed updated: $(wc -l < "$INTEL_DIR/abuse-ch-sslbl.intel") entries"
else
    warn "SSL Blacklist download failed"
fi

log "Threat intel update complete."

# Reload Zeek if running to pick up new intel
if command -v zeekctl &>/dev/null && zeekctl status 2>/dev/null | grep -q "running"; then
    log "Signaling Zeek to reload intel files..."
    zeekctl deploy 2>/dev/null || warn "Zeek reload failed — intel will load on next restart"
fi

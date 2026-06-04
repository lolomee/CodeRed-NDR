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

# Secure curl wrapper — always verify TLS, set timeout, fail on HTTP errors
# Never use --insecure or --no-check-certificate in this script.
secure_curl() {
    curl --silent --show-error \
         --fail \
         --max-time 120 \
         --retry 2 \
         --retry-delay 5 \
         --tlsv1.2 \
         --proto '=https' \
         "$@"
}

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

mkdir -p "$INTEL_DIR"

# Crash-safety: every file listed in Zeek's Intel::read_files MUST exist at Zeek
# startup or Zeek aborts. Seed a header-only stub for any feed file that does not
# exist yet, so a failed download (or first run) can never take Zeek down. Real
# feed data overwrites these stubs below.
for _f in urlhaus feodo sslbl malwarebazaar; do
    [ -f "$INTEL_DIR/abuse-ch-$_f.intel" ] || printf '%b\n' "$HEADER" > "$INTEL_DIR/abuse-ch-$_f.intel"
done

# ─── URLhaus (recent URLs) ───
log "Downloading URLhaus feed..."
if secure_curl -o "$TMP_DIR/urlhaus.csv" \
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
if secure_curl -o "$TMP_DIR/feodo.csv" \
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
if secure_curl -o "$TMP_DIR/sslbl.csv" \
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

# ─── MalwareBazaar (recent malware file hashes) ───
# Bounded "recent additions" feed (~few hundred samples) → Intel::FILE_HASH.
# This is what lets Zeek match files seen on the wire (files.log md5/sha256)
# against known malware — the file-reputation layer Suricata signatures miss.
log "Downloading MalwareBazaar feed..."
if secure_curl -o "$TMP_DIR/malwarebazaar.csv" \
    "https://bazaar.abuse.ch/export/csv/recent/" 2>/dev/null; then
    {
        printf '%b\n' "$HEADER"
        # Quoted, ", "-separated CSV: col2=sha256, col3=md5, col9=signature(family).
        # Emit both sha256 and md5; validate each is proper hex before writing.
        grep -vE '^#|^$|^"first_seen' "$TMP_DIR/malwarebazaar.csv" | \
        awk -F'", "' '{
            s=$2; m=$3; fam=$9;
            gsub(/"/,"",s); gsub(/"/,"",m); gsub(/"/,"",fam);
            gsub(/[ \t]/,"",s); gsub(/[ \t]/,"",m);
            if (fam==""||fam=="n/a") fam="malware sample";
            if (s ~ /^[0-9a-fA-F]{64}$/)
                printf "%s\tIntel::FILE_HASH\tabuse.ch MalwareBazaar\tMalware (%s)\thttps://bazaar.abuse.ch\n", s, fam;
            if (m ~ /^[0-9a-fA-F]{32}$/)
                printf "%s\tIntel::FILE_HASH\tabuse.ch MalwareBazaar\tMalware (%s)\thttps://bazaar.abuse.ch\n", m, fam;
        }'
    } > "$INTEL_DIR/abuse-ch-malwarebazaar.intel"
    log "MalwareBazaar feed updated: $(wc -l < "$INTEL_DIR/abuse-ch-malwarebazaar.intel") entries"
else
    warn "MalwareBazaar download failed"
fi

log "Threat intel update complete."

# Reload Zeek to pick up new intel. Prefer systemd (the canonical lifecycle
# manager on this sensor) — a bare `zeekctl deploy` starts a node systemd no
# longer tracks, leaving the service desynced. Fall back to zeekctl only when the
# service unit is absent (e.g. manual/dev installs).
if systemctl is-active --quiet codered-zeek 2>/dev/null; then
    log "Restarting Zeek via systemd to load new intel..."
    systemctl restart codered-zeek || warn "Zeek restart failed — intel will load on next restart"
elif command -v zeekctl &>/dev/null && zeekctl status 2>/dev/null | grep -q "running"; then
    log "Reloading Zeek via zeekctl to load new intel..."
    zeekctl deploy 2>/dev/null || warn "Zeek reload failed — intel will load on next restart"
fi

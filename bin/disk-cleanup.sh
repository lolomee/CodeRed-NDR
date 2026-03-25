#!/bin/bash
# CodeRed NDR - Disk Space Cleanup
set -euo pipefail

NSM_DIR="/nsm"
LOG="/var/log/codered/disk-cleanup.log"
THRESHOLD=85  # percentage

mkdir -p "$(dirname "$LOG")"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$LOG"; }

get_usage() {
    df --output=pcent "$NSM_DIR" 2>/dev/null | tail -1 | tr -dc '0-9'
}

USAGE=$(get_usage)
if (( USAGE < THRESHOLD )); then
    exit 0
fi

log "Disk usage at ${USAGE}% — starting cleanup"

# Phase 1: Old PCAPs (oldest first)
if (( $(get_usage) >= THRESHOLD )); then
    log "Phase 1: Cleaning old PCAPs..."
    find /nsm/pcap -name "*.pcap*" -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -n 50 | while read -r ts file; do
        rm -f "$file"
        log "Deleted PCAP: $file"
    done
fi

# Phase 2: Old Zeek logs (archived, not current)
if (( $(get_usage) >= THRESHOLD )); then
    log "Phase 2: Cleaning old Zeek logs..."
    find /nsm/zeek/logs -name "*.log.gz" -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -n 100 | while read -r ts file; do
        rm -f "$file"
        log "Deleted Zeek log: $file"
    done
fi

# Phase 3: Old Suricata logs
if (( $(get_usage) >= THRESHOLD )); then
    log "Phase 3: Cleaning old Suricata logs..."
    find /nsm/suricata/log -name "eve.json.*" -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -n 20 | while read -r ts file; do
        rm -f "$file"
        log "Deleted Suricata log: $file"
    done
fi

# Phase 4: Zeek extracted files
if (( $(get_usage) >= THRESHOLD )); then
    log "Phase 4: Cleaning extracted files..."
    find /nsm/zeek/extracted -type f -printf '%T+ %p\n' 2>/dev/null | sort | head -n 200 | while read -r ts file; do
        rm -f "$file"
        log "Deleted extracted: $file"
    done
fi

FINAL=$(get_usage)
log "Cleanup complete. Usage: ${FINAL}%"

#!/bin/bash
# CodeRed NDR - Suricata Rule Update
# Downloads ET/Open rules and reloads Suricata
set -euo pipefail

LOG="/var/log/codered/rule-update.log"
RULES_DIR="/var/lib/suricata/rules"
ET_URL="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"

mkdir -p /var/log/codered "$RULES_DIR"

log() {
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "${ts} [RULES] $*" | tee -a "$LOG"
    logger -t codered-rules "$*" 2>/dev/null || true
}

reload_suricata() {
    # Find the running Suricata. Its process comm is "Suricata-Main", so
    # `pgrep -x suricata` NEVER matches — use the pidfile, with a full
    # command-line pgrep as fallback.
    local pid=""
    if [ -f /var/run/suricata.pid ]; then
        pid=$(cat /var/run/suricata.pid 2>/dev/null || true)
        kill -0 "$pid" 2>/dev/null || pid=""
    fi
    [ -z "$pid" ] && pid=$(pgrep -f '[s]uricata .*-c ' | head -1 || true)

    if [ -z "$pid" ]; then
        log "Suricata not running -- rules will load on next start"
        return
    fi

    # SIGUSR2 triggers an in-place rule reload with no packet loss and no
    # dependency on the unix-command socket (the daemonized engine frequently
    # has no live socket). Fall back to suricatasc, then a full restart of the
    # correct unit (codered-suricata, NOT "suricata").
    if kill -USR2 "$pid" 2>/dev/null; then
        log "Rules reloaded live (SIGUSR2 -> pid ${pid})"
    elif suricatasc -c reload-rules 2>/dev/null; then
        log "Rules reloaded live (suricatasc)"
    elif systemctl restart codered-suricata.service 2>/dev/null; then
        log "Suricata restarted to load rules"
    else
        log "WARNING: Could not reload rules -- restart codered-suricata manually"
    fi
}

# Prefer suricata-update if available
if command -v suricata-update &>/dev/null; then
    log "Starting rule update via suricata-update..."
    suricata-update enable-source et/open 2>/dev/null || true
    if suricata-update 2>/dev/null; then
        RULE_COUNT=$(find "$RULES_DIR" -name "*.rules" -exec grep -c "^alert\|^drop\|^reject" {} + 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
        log "suricata-update complete: ${RULE_COUNT} rules"
        reload_suricata
        echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") rules=${RULE_COUNT}" > /var/log/codered/last-rule-update.log
        exit 0
    else
        log "WARNING: suricata-update failed, falling back to manual download"
    fi
fi

# Fallback: manual download
log "Starting ET rule update (manual download)..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

if ! curl -sSL --connect-timeout 30 --max-time 120 -o "${TMP_DIR}/emerging.rules.tar.gz" "${ET_URL}"; then
    log "ERROR: Failed to download rules"
    exit 1
fi

if ! file "${TMP_DIR}/emerging.rules.tar.gz" | grep -q gzip; then
    log "ERROR: Invalid download (not gzip)"
    exit 1
fi

mkdir -p "${TMP_DIR}/extracted"
tar xzf "${TMP_DIR}/emerging.rules.tar.gz" -C "${TMP_DIR}/extracted"
RULE_COUNT=$(grep -r "^alert\|^drop\|^reject" "${TMP_DIR}/extracted/" 2>/dev/null | wc -l)
log "Downloaded ${RULE_COUNT} rules"

if [ "$RULE_COUNT" -lt 1000 ]; then
    log "WARNING: Rule count too low (${RULE_COUNT}). Skipping to protect existing rules."
    exit 1
fi

# Backup existing rules (keep last 3 backups)
if [ -d "$RULES_DIR" ] && ls "$RULES_DIR"/*.rules &>/dev/null; then
    cp -r "$RULES_DIR" "${RULES_DIR}.bak.$(date +%Y%m%d)" 2>/dev/null || true
    ls -dt "${RULES_DIR}".bak.* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
fi

find "${TMP_DIR}/extracted" -name "*.rules" -exec cp {} "$RULES_DIR/" \;

reload_suricata

echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") rules=${RULE_COUNT}" > /var/log/codered/last-rule-update.log
log "Rule update complete: ${RULE_COUNT} rules"

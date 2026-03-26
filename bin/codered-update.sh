#!/bin/bash
set -euo pipefail
LOG="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
log() { echo "${TIMESTAMP} [UPDATE] $*" | tee -a "$LOG"; logger -t codered-update "$*"; }
log "Starting CodeRed auto-update..."
[ -d "$REPO_DIR/.git" ] || { log "Repo not configured."; exit 0; }
cd "$REPO_DIR"
BEFORE=$(git rev-parse HEAD)
git pull --ff-only origin "$(git branch --show-current)" >> "$LOG" 2>&1 || { log "ERROR: git pull failed"; exit 1; }
AFTER=$(git rev-parse HEAD)
[ "$BEFORE" = "$AFTER" ] && { log "No updates."; echo "$TIMESTAMP" > /var/log/codered/last-update.log; exit 0; }
log "Updates: ${BEFORE:0:8} -> ${AFTER:0:8}"
[ -f "$REPO_DIR/shell/cli.py" ] && {
    chattr -i /opt/codered/shell/cli.py 2>/dev/null || true
    cp "$REPO_DIR/shell/cli.py" /opt/codered/shell/cli.py
    chattr +i /opt/codered/shell/cli.py 2>/dev/null || true
}
[ -f "$REPO_DIR/VERSION" ] && cp "$REPO_DIR/VERSION" /opt/codered/VERSION
[ -f "$REPO_DIR/conf/codered.defaults" ] && cp "$REPO_DIR/conf/codered.defaults" /etc/codered/codered.defaults
[ -d "$REPO_DIR/bin" ] && { chmod 750 "$REPO_DIR"/bin/*.sh 2>/dev/null; cp "$REPO_DIR"/bin/*.sh /opt/codered/bin/ 2>/dev/null || true; }
[ -f "$REPO_DIR/firstboot/firstboot.sh" ] && cp "$REPO_DIR/firstboot/firstboot.sh" /opt/codered/firstboot/firstboot.sh

# Sync Zeek detection scripts — new detections deployed to existing sensors
if [ -d "$REPO_DIR/zeek/codered-detections" ]; then
    mkdir -p /opt/codered/zeek
    cp -r "$REPO_DIR/zeek/codered-detections" /opt/codered/zeek/
    COUNT=$(ls /opt/codered/zeek/codered-detections/*.zeek 2>/dev/null | wc -l)
    log "Zeek detection scripts synced: ${COUNT} scripts"
fi

# Sync ML engine (restart if running to pick up changes)
if [ -f "$REPO_DIR/ml/codered-ml.py" ]; then
    mkdir -p /opt/codered/ml
    cp "$REPO_DIR/ml/codered-ml.py" /opt/codered/ml/codered-ml.py
    chmod 750 /opt/codered/ml/codered-ml.py
    systemctl is-active codered-ml &>/dev/null && systemctl restart codered-ml 2>/dev/null && log "ML engine restarted" || true
fi

# NOTE: local.zeek is NOT synced — it holds live sensor-specific config
# (Zeek digest salt, cloud_mode VXLAN settings). Only detection scripts are synced.

echo "$TIMESTAMP" > /var/log/codered/last-update.log
log "Update complete."

#!/bin/bash
set -euo pipefail
LOG="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
log() { echo "${TIMESTAMP} [UPDATE] $*" | tee -a "$LOG"; logger -t codered-update "$*"; }
log "Starting CodeRed auto-update..."
[ -d "$REPO_DIR/.git" ] || { log "Repo not configured."; exit 0; }
cd "$REPO_DIR"

# Configure git credentials if token is available (private repo support)
TOKEN_FILE="/etc/codered/.git-token"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    git remote set-url origin "https://${TOKEN}@github.com/lolomee/CodeRed-NDR.git" 2>/dev/null || true
fi

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
if [ -d "$REPO_DIR/bin" ]; then
    # Sync shell helpers
    chmod 750 "$REPO_DIR"/bin/*.sh 2>/dev/null || true
    cp "$REPO_DIR"/bin/*.sh /opt/codered/bin/ 2>/dev/null || true
    # Sync Python helpers (e.g. codered-syslog-forwarder.py). Previously skipped,
    # which meant new daemon code never reached customers via auto-update.
    if compgen -G "$REPO_DIR/bin/*.py" > /dev/null; then
        FWD_BEFORE=$(sha256sum /opt/codered/bin/codered-syslog-forwarder.py 2>/dev/null | awk '{print $1}')
        chmod 750 "$REPO_DIR"/bin/*.py 2>/dev/null || true
        cp "$REPO_DIR"/bin/*.py /opt/codered/bin/ 2>/dev/null || true
        FWD_AFTER=$(sha256sum /opt/codered/bin/codered-syslog-forwarder.py 2>/dev/null | awk '{print $1}')
        if [ -n "$FWD_AFTER" ] && [ "$FWD_BEFORE" != "$FWD_AFTER" ]; then
            systemctl is-active codered-syslog &>/dev/null \
                && systemctl restart codered-syslog 2>/dev/null \
                && log "Syslog forwarder restarted after update" \
                || true
        fi
    fi
fi
[ -f "$REPO_DIR/firstboot/firstboot.sh" ] && cp "$REPO_DIR/firstboot/firstboot.sh" /opt/codered/firstboot/firstboot.sh

# Sync logrotate config — without this, daemon logs grow without bound.
if [ -f "$REPO_DIR/conf/codered.logrotate" ]; then
    install -m 0644 -o root -g root "$REPO_DIR/conf/codered.logrotate" \
        /etc/logrotate.d/codered 2>/dev/null && log "Logrotate config synced"
fi

# Sync the universal systemd hardening drop-in into each codered-* service's
# .d/ directory. Drop-ins survive unit-file replacement, so even if a future
# install.sh writes new base unit files, the operator's hardening stays in
# place. Reload systemd at the end if anything changed.
if [ -f "$REPO_DIR/conf/codered-hardening.conf" ]; then
    HARDENING_CHANGED=0
    for svc in codered-zeek codered-suricata codered-syslog codered-ml codered-update; do
        UNIT="/etc/systemd/system/${svc}.service"
        # Only install if the base unit exists on this sensor.
        [ -f "$UNIT" ] || continue
        DROPIN_DIR="/etc/systemd/system/${svc}.service.d"
        DROPIN="$DROPIN_DIR/hardening.conf"
        mkdir -p "$DROPIN_DIR"
        if ! cmp -s "$REPO_DIR/conf/codered-hardening.conf" "$DROPIN" 2>/dev/null; then
            install -m 0644 -o root -g root \
                "$REPO_DIR/conf/codered-hardening.conf" "$DROPIN"
            HARDENING_CHANGED=1
        fi
    done
    if [ "$HARDENING_CHANGED" = "1" ]; then
        systemctl daemon-reload 2>/dev/null && log "systemd hardening drop-ins synced; daemon reloaded"
    fi
fi

# Sync systemd unit files themselves. Previously these were write-once at
# install time, so any subsequent fix to a unit (ExecStart, Restart, etc.)
# could never reach customers via auto-update. Operator overrides live in
# .d/ drop-ins so they are preserved across this sync.
if [ -d "$REPO_DIR/conf/systemd" ]; then
    UNIT_CHANGED=0
    for f in "$REPO_DIR/conf/systemd"/codered-*.service "$REPO_DIR/conf/systemd"/codered-*.timer; do
        [ -f "$f" ] || continue
        BASENAME=$(basename "$f")
        DEST="/etc/systemd/system/$BASENAME"
        if ! cmp -s "$f" "$DEST" 2>/dev/null; then
            install -m 0644 -o root -g root "$f" "$DEST"
            UNIT_CHANGED=1
            log "Updated systemd unit: $BASENAME"
        fi
    done
    if [ "$UNIT_CHANGED" = "1" ]; then
        systemctl daemon-reload 2>/dev/null
    fi
fi

# Sync user-facing docs so customers can read updated guides locally.
if [ -d "$REPO_DIR/docs" ]; then
    mkdir -p /opt/codered/docs
    cp "$REPO_DIR/docs"/*.html /opt/codered/docs/ 2>/dev/null || true
fi

# Sync Filebeat output templates (auto-generated config is still written by
# cli.py at runtime, but the templates may be referenced by it).
if [ -d "$REPO_DIR/filebeat" ]; then
    mkdir -p /opt/codered/filebeat
    cp "$REPO_DIR/filebeat"/* /opt/codered/filebeat/ 2>/dev/null || true
fi

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

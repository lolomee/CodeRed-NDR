#!/bin/bash
# CodeRed NDR - Auto-Update Script
# Pulls latest Salt states from central repo and applies them.

set -euo pipefail

LOG_FILE="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
SALT_LOCAL="/opt/so/saltstack/local"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() {
    echo "${TIMESTAMP} [UPDATE] $*" | tee -a "$LOG_FILE"
    logger -t codered-update "$*"
}

log "Starting CodeRed auto-update..."

# Check if repo exists
if [ ! -d "$REPO_DIR/.git" ]; then
    log "Update repo not configured or not cloned. Skipping."
    exit 0
fi

# Pull latest changes
cd "$REPO_DIR"
BEFORE=$(git rev-parse HEAD)

if ! git pull --ff-only origin "$(git branch --show-current)" >> "$LOG_FILE" 2>&1; then
    log "ERROR: git pull failed. Manual intervention may be required."
    exit 1
fi

AFTER=$(git rev-parse HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
    log "No updates available. Current: ${BEFORE:0:8}"
    echo "$TIMESTAMP" > /var/log/codered/last-update.log
    exit 0
fi

log "Updates found: ${BEFORE:0:8} -> ${AFTER:0:8}"
log "Changes: $(git log --oneline "$BEFORE".."$AFTER" | head -20)"

# Copy updated Salt states
if [ -d "$REPO_DIR/salt/states/codered" ]; then
    log "Updating Salt states..."
    cp -r "$REPO_DIR/salt/states/codered" "$SALT_LOCAL/salt/"
fi

if [ -d "$REPO_DIR/salt/pillar/codered" ]; then
    log "Updating Salt pillars..."
    cp -r "$REPO_DIR/salt/pillar/codered" "$SALT_LOCAL/pillar/"
fi

# Update shell and firstboot scripts
if [ -d "$REPO_DIR/shell" ]; then
    log "Updating shell scripts..."
    # Remove immutable flags temporarily
    chattr -i /opt/codered/shell/*.py 2>/dev/null || true
    cp "$REPO_DIR/shell/"*.py /opt/codered/shell/
    chattr +i /opt/codered/shell/menu.py /opt/codered/shell/actions.py 2>/dev/null || true
fi

# Update version
if [ -f "$REPO_DIR/VERSION" ]; then
    cp "$REPO_DIR/VERSION" /opt/codered/VERSION
fi

# Apply Salt states
log "Applying Salt states..."
if salt-call --local state.apply codered >> "$LOG_FILE" 2>&1; then
    log "Salt states applied successfully."
else
    log "WARNING: Salt state apply had errors. Check $LOG_FILE for details."
fi

# Record update timestamp
echo "$TIMESTAMP" > /var/log/codered/last-update.log

# Set grain for tracking
salt-call --local grains.setval codered '{"last_update": "'"$TIMESTAMP"'", "version": "'"$(cat /opt/codered/VERSION 2>/dev/null || echo unknown)"'"}' 2>/dev/null || true

log "Update complete."

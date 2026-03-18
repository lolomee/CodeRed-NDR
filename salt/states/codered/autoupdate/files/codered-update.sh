#!/bin/bash
# CodeRed NDR - Auto-Update Script (Standalone Mode)
# Pulls latest code from central repo and updates sensor files.

set -euo pipefail

LOG_FILE="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
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

# Update CLI
if [ -f "$REPO_DIR/shell/cli.py" ]; then
    log "Updating CLI..."
    chattr -i /opt/codered/shell/cli.py 2>/dev/null || true
    cp "$REPO_DIR/shell/cli.py" /opt/codered/shell/cli.py
    chmod 755 /opt/codered/shell/cli.py
    chattr +i /opt/codered/shell/cli.py 2>/dev/null || true
fi

# Update version
if [ -f "$REPO_DIR/VERSION" ]; then
    cp "$REPO_DIR/VERSION" /opt/codered/VERSION
fi

# Update defaults config
if [ -f "$REPO_DIR/conf/codered.defaults" ]; then
    cp "$REPO_DIR/conf/codered.defaults" /etc/codered/codered.defaults
fi

# Update rule updater script
if [ -f "$REPO_DIR/install.sh" ]; then
    log "Install script available for reference."
fi

# Record update timestamp
echo "$TIMESTAMP" > /var/log/codered/last-update.log

log "Update complete."

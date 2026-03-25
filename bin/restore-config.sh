#!/bin/bash
# CodeRed NDR - Configuration Restore
set -euo pipefail

BACKUP_DIR="/var/lib/codered/backups"

if [ $# -eq 0 ]; then
    echo "Available backups:"
    ls -lt "$BACKUP_DIR"/codered-config-*.tar.gz 2>/dev/null | awk '{print NR". "$NF, $6, $7, $8}'
    echo ""
    read -rp "Select backup number (or path): " CHOICE
    if [[ "$CHOICE" =~ ^[0-9]+$ ]]; then
        BACKUP_FILE=$(ls -t "$BACKUP_DIR"/codered-config-*.tar.gz 2>/dev/null | sed -n "${CHOICE}p")
    else
        BACKUP_FILE="$CHOICE"
    fi
else
    BACKUP_FILE="$1"
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup not found: $BACKUP_FILE"
    exit 1
fi

echo "Restoring from: $BACKUP_FILE"
read -rp "This will overwrite current config. Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

tar xzf "$BACKUP_FILE" -C /

echo "Config restored. Restarting services..."
systemctl restart codered-zeek codered-suricata filebeat
echo "Done."
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) restore=$BACKUP_FILE" >> /var/log/codered/audit.log

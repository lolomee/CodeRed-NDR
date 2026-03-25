#!/bin/bash
# CodeRed NDR - Configuration Backup
set -euo pipefail

BACKUP_DIR="/var/lib/codered/backups"
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/codered-config-${TIMESTAMP}.tar.gz"

tar czf "$BACKUP_FILE" \
    /etc/codered/sensor.conf \
    /etc/codered/codered.defaults \
    /opt/zeek/etc/node.cfg \
    /opt/zeek/share/zeek/site/local.zeek \
    /etc/filebeat/filebeat.yml \
    /etc/filebeat/modules.d/ \
    /opt/zeek/share/zeek/site/intel/ \
    2>/dev/null || true

chmod 600 "$BACKUP_FILE"

# Keep only last 10 backups
ls -t "$BACKUP_DIR"/codered-config-*.tar.gz 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true

echo "Backup saved: $BACKUP_FILE"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) backup=$BACKUP_FILE" >> /var/log/codered/audit.log

#!/bin/bash
# CodeRed NDR - Auto-resize disk partition and filesystem
# Runs on every boot to pick up VMware disk expansions automatically
set -euo pipefail

LOG="/var/log/codered/disk-resize.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() { echo "$TIMESTAMP [RESIZE] $*" >> "$LOG" 2>/dev/null; }

# Find the root device and partition
ROOT_DEV=$(findmnt -n -o SOURCE /)
if [ -z "$ROOT_DEV" ]; then
    log "Could not determine root device"
    exit 0
fi

# Determine the disk and partition number
# e.g., /dev/sda1 → disk=/dev/sda, partnum=1
# e.g., /dev/nvme0n1p1 → disk=/dev/nvme0n1, partnum=1
if [[ "$ROOT_DEV" =~ ^(/dev/nvme[0-9]+n[0-9]+)p([0-9]+)$ ]]; then
    DISK="${BASH_REMATCH[1]}"
    PARTNUM="${BASH_REMATCH[2]}"
elif [[ "$ROOT_DEV" =~ ^(/dev/[a-z]+)([0-9]+)$ ]]; then
    DISK="${BASH_REMATCH[1]}"
    PARTNUM="${BASH_REMATCH[2]}"
elif [[ "$ROOT_DEV" =~ ^(/dev/xvd[a-z]+)([0-9]+)$ ]]; then
    DISK="${BASH_REMATCH[1]}"
    PARTNUM="${BASH_REMATCH[2]}"
else
    log "Unsupported disk layout: $ROOT_DEV"
    exit 0
fi

# Get current sizes
PART_SIZE_BEFORE=$(lsblk -b -n -o SIZE "$ROOT_DEV" 2>/dev/null | head -1)
DISK_SIZE=$(lsblk -b -n -o SIZE "$DISK" 2>/dev/null | head -1)

# Try to grow the partition
if command -v growpart &>/dev/null; then
    RESULT=$(growpart "$DISK" "$PARTNUM" 2>&1) || true
    if echo "$RESULT" | grep -q "CHANGED"; then
        log "Partition $ROOT_DEV grown on $DISK"
    elif echo "$RESULT" | grep -q "NOCHANGE"; then
        # No resize needed
        exit 0
    else
        log "growpart: $RESULT"
    fi
else
    log "growpart not found — install cloud-guest-utils"
    exit 0
fi

# Resize the filesystem
FSTYPE=$(findmnt -n -o FSTYPE /)
case "$FSTYPE" in
    ext4|ext3|ext2)
        resize2fs "$ROOT_DEV" >> "$LOG" 2>&1 && log "Filesystem resized (ext)" || log "resize2fs failed"
        ;;
    xfs)
        xfs_growfs / >> "$LOG" 2>&1 && log "Filesystem resized (xfs)" || log "xfs_growfs failed"
        ;;
    btrfs)
        btrfs filesystem resize max / >> "$LOG" 2>&1 && log "Filesystem resized (btrfs)" || log "btrfs resize failed"
        ;;
    *)
        log "Unsupported filesystem: $FSTYPE"
        ;;
esac

PART_SIZE_AFTER=$(lsblk -b -n -o SIZE "$ROOT_DEV" 2>/dev/null | head -1)
if [ "$PART_SIZE_BEFORE" != "$PART_SIZE_AFTER" ]; then
    BEFORE_GB=$((PART_SIZE_BEFORE / 1073741824))
    AFTER_GB=$((PART_SIZE_AFTER / 1073741824))
    log "Disk resized: ${BEFORE_GB}GB → ${AFTER_GB}GB"
fi

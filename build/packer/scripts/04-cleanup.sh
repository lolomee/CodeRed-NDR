#!/bin/bash
# CodeRed NDR - Pre-Export Cleanup
set -euo pipefail

echo "=== CodeRed Sensor Build: Step 4 - Cleanup ==="

# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Reset machine-id
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

# Clear logs
find /var/log -type f -name '*.log' -exec truncate -s 0 {} \;
journalctl --vacuum-time=1s 2>/dev/null || true

# Clear shell history
rm -f /root/.bash_history /home/*/.bash_history
unset HISTFILE

# Clear temp files
rm -rf /tmp/* /var/tmp/*

# Clear package cache
dnf clean all 2>/dev/null || apt-get clean 2>/dev/null || true

# Remove Packer artifacts
rm -rf /opt/codered/.git 2>/dev/null || true
rm -rf /opt/codered/build 2>/dev/null || true
rm -rf /opt/codered/tests 2>/dev/null || true
rm -f /opt/codered/Makefile 2>/dev/null || true

# Ensure first-boot wizard will trigger
rm -f /etc/codered/.setup-complete

# Zero free space for better OVA compression
echo "Zeroing free space (this may take a while)..."
dd if=/dev/zero of=/zero bs=1M 2>/dev/null || true
rm -f /zero
sync

echo "Cleanup complete. Ready for export."

#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║         CodeRed NDR - Uninstall Script                   ║
# ║                                                          ║
# ║  Usage: sudo bash uninstall.sh                           ║
# ╚══════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash uninstall.sh"; exit 1; }

echo ""
echo -e "${RED}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           CodeRed NDR - Uninstall                        ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  This will:"
echo "    - Stop and disable Zeek, Suricata, Filebeat"
echo "    - Remove CodeRed NDR CLI and configs"
echo "    - Remove systemd timers (rule update, auto-update)"
echo "    - Remove kernel hardening sysctl settings"
echo "    - Remove the 'coderedndr' command"
echo ""
echo "  This will NOT:"
echo "    - Uninstall Zeek, Suricata, or Filebeat packages"
echo "    - Delete /nsm/ log data"
echo "    - Modify your SSH configuration"
echo ""

read -p "  Are you sure you want to uninstall CodeRed NDR? (type YES): " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo "  Cancelled."
    exit 0
fi

echo ""

# Stop services
log "Stopping services..."
/opt/zeek/bin/zeekctl stop 2>/dev/null || true
systemctl stop suricata 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true
systemctl disable suricata 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true

# Disable timers
log "Disabling timers..."
systemctl disable --now codered-rule-update.timer 2>/dev/null || true
systemctl disable --now codered-update.timer 2>/dev/null || true

# Remove systemd units
rm -f /etc/systemd/system/codered-rule-update.service
rm -f /etc/systemd/system/codered-rule-update.timer
rm -f /etc/systemd/system/codered-update.service
rm -f /etc/systemd/system/codered-update.timer
systemctl daemon-reload
log "Systemd units removed."

# Remove coderedndr command
rm -f /usr/local/bin/coderedndr
log "Command 'coderedndr' removed."

# Remove CodeRed files
chattr -i /opt/codered/shell/cli.py 2>/dev/null || true
rm -rf /opt/codered
log "CodeRed NDR files removed."

# Remove configs
rm -rf /etc/codered
rm -f /etc/logrotate.d/codered-ndr
log "Configs removed."

# Remove kernel hardening
rm -f /etc/sysctl.d/99-codered-hardening.conf
sysctl --system >/dev/null 2>&1
log "Kernel hardening reverted."

# Remove logs (optional)
read -p "  Delete CodeRed NDR logs (/var/log/codered/)? (y/N): " DEL_LOGS
if [[ "$DEL_LOGS" =~ ^[Yy]$ ]]; then
    rm -rf /var/log/codered
    log "Logs deleted."
else
    log "Logs kept at /var/log/codered/"
fi

echo ""
echo -e "${GREEN}${BOLD}  CodeRed NDR uninstalled successfully.${NC}"
echo ""
echo "  Zeek, Suricata, and Filebeat packages are still installed."
echo "  To remove them completely:"
echo "    sudo apt-get remove --purge zeek suricata filebeat"
echo ""

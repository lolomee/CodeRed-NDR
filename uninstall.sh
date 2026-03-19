#!/bin/bash
# CodeRed NDR - Uninstaller
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}"
echo "  CodeRed NDR - Uninstaller"
echo -e "${NC}"

[ "$(id -u)" -eq 0 ] || { echo -e "${RED}[x]${NC} Must be run as root. Use: sudo bash uninstall.sh"; exit 1; }

if [ ! -f /opt/codered/VERSION ]; then
    echo -e "${YELLOW}[!]${NC} CodeRed NDR is not installed."
    exit 0
fi

INSTALLED_VER=$(cat /opt/codered/VERSION)
echo "  Found CodeRed NDR v${INSTALLED_VER}"
echo ""
read -p "  Are you sure you want to uninstall? (y/N): " REPLY
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    echo "  Cancelled."
    exit 0
fi

echo ""

# Stop services
echo -e "${YELLOW}[1/5]${NC} Stopping services..."
systemctl stop codered-rule-update.timer 2>/dev/null || true
systemctl stop codered-update.timer 2>/dev/null || true
systemctl disable codered-rule-update.timer 2>/dev/null || true
systemctl disable codered-update.timer 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Services stopped."

# Remove systemd units
echo -e "${YELLOW}[2/5]${NC} Removing systemd units..."
rm -f /etc/systemd/system/codered-rule-update.service
rm -f /etc/systemd/system/codered-rule-update.timer
rm -f /etc/systemd/system/codered-update.service
rm -f /etc/systemd/system/codered-update.timer
systemctl daemon-reload
echo -e "${GREEN}[+]${NC} Systemd units removed."

# Remove CodeRed files
echo -e "${YELLOW}[3/5]${NC} Removing CodeRed NDR files..."
rm -rf /opt/codered
rm -rf /etc/codered
rm -rf /var/log/codered
rm -f /usr/local/bin/coderedndr
echo -e "${GREEN}[+]${NC} Files removed."

# Remove NSM data
echo ""
read -p "  Remove /nsm data directory (Zeek logs, pcap, Suricata logs)? (y/N): " REMOVE_NSM
if [[ "$REMOVE_NSM" =~ ^[Yy]$ ]]; then
    rm -rf /nsm
    echo -e "${GREEN}[+]${NC} /nsm removed."
else
    echo -e "${YELLOW}[!]${NC} /nsm kept."
fi

# Clean up repo keys
echo -e "${YELLOW}[4/5]${NC} Cleaning up apt repo files..."
rm -f /etc/apt/sources.list.d/zeek.list
rm -f /etc/apt/keyrings/security_zeek.gpg
rm -f /etc/apt/trusted.gpg.d/zeek.gpg
rm -f /etc/apt/trusted.gpg.d/security_zeek.gpg
echo -e "${GREEN}[+]${NC} Apt files cleaned."

# Remove kernel hardening if present
echo -e "${YELLOW}[5/5]${NC} Checking kernel hardening..."
if [ -f /etc/sysctl.d/99-codered-hardening.conf ]; then
    rm -f /etc/sysctl.d/99-codered-hardening.conf
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}[+]${NC} Kernel hardening reverted."
else
    echo -e "${GREEN}[+]${NC} No kernel hardening found."
fi

echo ""
echo -e "${GREEN}${BOLD}  CodeRed NDR uninstalled successfully.${NC}"
echo ""
echo "  Note: Zeek, Suricata, and Filebeat packages were NOT removed."
echo "  To remove them manually:"
echo "    sudo apt remove --purge zeek suricata filebeat"
echo ""

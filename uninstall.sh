#!/bin/bash
# CodeRed NDR - Full Uninstaller
# Removes everything installed by install.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}"
echo "  CodeRed NDR - Full Uninstaller"
echo -e "${NC}"

[ "$(id -u)" -eq 0 ] || { echo -e "${RED}[x]${NC} Must be run as root. Use: sudo bash uninstall.sh"; exit 1; }

echo "  This will completely remove CodeRed NDR and all components"
echo "  including Zeek, Suricata, Filebeat, and all data."
echo ""
read -p "  Are you sure? (y/N): " REPLY
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    echo "  Cancelled."
    exit 0
fi

echo ""

# Stop and disable services
echo -e "${YELLOW}[1/7]${NC} Stopping all services..."
systemctl stop zeek 2>/dev/null || true
systemctl stop suricata 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true
systemctl stop codered-rule-update.timer 2>/dev/null || true
systemctl stop codered-update.timer 2>/dev/null || true
systemctl disable zeek 2>/dev/null || true
systemctl disable suricata 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true
systemctl disable codered-rule-update.timer 2>/dev/null || true
systemctl disable codered-update.timer 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Services stopped."

# Remove systemd units
echo -e "${YELLOW}[2/7]${NC} Removing systemd units..."
rm -f /etc/systemd/system/codered-rule-update.service
rm -f /etc/systemd/system/codered-rule-update.timer
rm -f /etc/systemd/system/codered-update.service
rm -f /etc/systemd/system/codered-update.timer
systemctl daemon-reload
echo -e "${GREEN}[+]${NC} Systemd units removed."

# Remove packages
echo -e "${YELLOW}[3/7]${NC} Removing Zeek, Suricata, Filebeat..."
export DEBIAN_FRONTEND=noninteractive
apt-get remove --purge -y zeek suricata suricata-update filebeat 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true
rm -rf /opt/zeek
rm -rf /etc/suricata
rm -rf /var/lib/suricata
rm -rf /var/log/suricata
echo -e "${GREEN}[+]${NC} Packages removed."

# Remove CodeRed NDR files
echo -e "${YELLOW}[4/7]${NC} Removing CodeRed NDR files..."
rm -rf /opt/codered
rm -rf /etc/codered
rm -rf /var/log/codered
rm -rf /nsm
rm -f /usr/local/bin/coderedndr
echo -e "${GREEN}[+]${NC} CodeRed NDR files removed."

# Remove profile scripts
echo -e "${YELLOW}[5/7]${NC} Removing profile scripts..."
rm -f /etc/profile.d/codered-cli.sh
rm -f /etc/profile.d/zeek-path.sh
echo -e "${GREEN}[+]${NC} Profile scripts removed."

# Remove apt repos and keys
echo -e "${YELLOW}[6/7]${NC} Removing apt repos and keys..."
rm -f /etc/apt/sources.list.d/zeek.list
rm -f /etc/apt/sources.list.d/elastic-8.x.list
rm -f /etc/apt/keyrings/security_zeek.gpg
rm -f /etc/apt/trusted.gpg.d/zeek.gpg
rm -f /etc/apt/trusted.gpg.d/security_zeek.gpg
rm -f /etc/apt/trusted.gpg.d/elastic.gpg
apt-get update -qq 2>/dev/null || true
echo -e "${GREEN}[+]${NC} Apt repos cleaned."

# Remove kernel hardening and GeoIP
echo -e "${YELLOW}[7/7]${NC} Removing kernel hardening and GeoIP..."
if [ -f /etc/sysctl.d/99-codered-hardening.conf ]; then
    rm -f /etc/sysctl.d/99-codered-hardening.conf
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}[+]${NC} Kernel hardening reverted."
else
    echo -e "${GREEN}[+]${NC} No kernel hardening found."
fi
rm -f /usr/share/GeoIP/GeoLite2-City.mmdb
echo -e "${GREEN}[+]${NC} GeoIP database removed."

echo ""
echo -e "${GREEN}${BOLD}  CodeRed NDR fully uninstalled.${NC}"
echo ""

#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         CodeRed NDR - Complete Uninstaller                    ║
# ║                                                               ║
# ║  Usage: sudo bash uninstall.sh                                ║
# ║                                                               ║
# ║  Cleanly removes all CodeRed NDR components from the system.  ║
# ║  Optionally removes data, packages, and OVA-specific users.   ║
# ╚══════════════════════════════════════════════════════════════╝

set -uo pipefail

# ─── Colors ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Log file ────────────────────────────────────────────────
LOGFILE="/tmp/codered-uninstall.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== CodeRed NDR Uninstall started at $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >> "$LOGFILE"

# ─── Helpers ─────────────────────────────────────────────────
log()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# ─── Root check ──────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || err "This script must be run as root: sudo bash uninstall.sh"

# ═════════════════════════════════════════════════════════════
# Show what will be removed and confirm
# ═════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${RED}"
echo "  +----------------------------------------------------------+"
echo "  |         CodeRed NDR - Uninstaller                        |"
echo "  +----------------------------------------------------------+"
echo -e "${NC}"
echo ""
echo -e "${BOLD}The following will be removed:${NC}"
echo ""
echo "  Systemd services and timers:"
echo "    - codered-zeek, codered-suricata, codered-pcap"
echo "    - codered-rule-update (.service + .timer)"
echo "    - codered-update (.service + .timer)"
echo "    - codered-intel-update (.service + .timer)"
echo "    - codered-disk-cleanup (.service + .timer)"
echo "    - codered-disk-resize, codered-firstboot"
echo "    - codered-remove-builder"
echo "    - regenerate-ssh-keys"
echo "    - filebeat drop-in override (codered.conf)"
echo ""
echo "  Software directories:"
echo "    - /opt/codered/                (CLI, scripts, config)"
echo "    - /opt/zeek/share/zeek/site/codered-detections/"
echo "    - /opt/zeek/share/zeek/site/intel/"
echo ""
echo "  Configuration files:"
echo "    - /etc/codered/                (sensor.conf, defaults)"
echo "    - /etc/sudoers.d/codered-ndr"
echo "    - /etc/sudoers.d/codered-admin"
echo "    - /etc/logrotate.d/codered-ndr"
echo "    - /usr/local/bin/coderedndr    (CLI symlink)"
echo "    - /etc/profile.d/zeek-path.sh"
echo "    - /etc/pam.d/su-codered"
echo "    - /etc/ssh/sshd_config.d/90-codered-hardening.conf"
echo "    - /etc/update-motd.d/00-codered-banner"
echo "    - /etc/netplan/01-codered-default.yaml"
echo ""
echo "  State and log files:"
echo "    - /var/log/codered/"
echo "    - /var/lib/codered/"
echo "    - /etc/codered/.setup-complete"
echo ""
echo "  Filebeat modules:"
echo "    - modules.d/zeek.yml, suricata.yml (enabled/disabled)"
echo ""
echo -e "${YELLOW}${BOLD}  WARNING: This action cannot be undone.${NC}"
echo ""
echo -e "  To proceed, type ${BOLD}UNINSTALL${NC} (all caps) and press Enter."
echo ""

# Read confirmation from terminal even if script is piped
if [ -t 0 ]; then
    read -rp "  > " CONFIRM
else
    if [ -r /dev/tty ]; then
        read -rp "  > " CONFIRM < /dev/tty
    else
        err "Cannot read confirmation in non-interactive mode. Run interactively."
    fi
fi

if [ "$CONFIRM" != "UNINSTALL" ]; then
    echo ""
    echo "  Aborted. Nothing was removed."
    exit 0
fi

echo ""
info "Proceeding with uninstall..."
echo ""

# ═════════════════════════════════════════════════════════════
# Optional: Remove /nsm/ data (logs, pcaps, extracted files)
# ═════════════════════════════════════════════════════════════
REMOVE_DATA=false
echo -e "  ${BOLD}Remove /nsm/ data directory?${NC} (Zeek logs, Suricata logs, PCAPs)"
echo "  This contains all captured network data. Default: keep"
echo ""

if [ -t 0 ]; then
    read -rp "  Remove /nsm/? (y/N): " DATA_REPLY
else
    read -rp "  Remove /nsm/? (y/N): " DATA_REPLY < /dev/tty 2>/dev/null || DATA_REPLY="N"
fi
if [[ "$DATA_REPLY" =~ ^[Yy]$ ]]; then
    REMOVE_DATA=true
fi
echo ""

# ═════════════════════════════════════════════════════════════
# Optional: Uninstall Zeek, Suricata, Filebeat packages
# ═════════════════════════════════════════════════════════════
REMOVE_PACKAGES=false
echo -e "  ${BOLD}Uninstall Zeek, Suricata, and Filebeat packages?${NC}"
echo "  Default: keep packages (you may want them for other uses)"
echo ""

if [ -t 0 ]; then
    read -rp "  Remove packages? (y/N): " PKG_REPLY
else
    read -rp "  Remove packages? (y/N): " PKG_REPLY < /dev/tty 2>/dev/null || PKG_REPLY="N"
fi
if [[ "$PKG_REPLY" =~ ^[Yy]$ ]]; then
    REMOVE_PACKAGES=true
fi
echo ""

# ═════════════════════════════════════════════════════════════
# Optional: Remove OVA users (coderedndr, cradmin)
# ═════════════════════════════════════════════════════════════
REMOVE_USERS=false
OVA_USERS_EXIST=false
if id coderedndr &>/dev/null || id cradmin &>/dev/null; then
    OVA_USERS_EXIST=true
    echo -e "  ${BOLD}Remove OVA-specific users?${NC}"
    FOUND_USERS=""
    id coderedndr &>/dev/null && FOUND_USERS="coderedndr"
    id cradmin &>/dev/null && FOUND_USERS="${FOUND_USERS:+$FOUND_USERS, }cradmin"
    echo "  Found: $FOUND_USERS"
    echo "  These were created by the OVA preparation script."
    echo "  Default: keep users"
    echo ""

    if [ -t 0 ]; then
        read -rp "  Remove these users and their home directories? (y/N): " USER_REPLY
    else
        read -rp "  Remove these users and their home directories? (y/N): " USER_REPLY < /dev/tty 2>/dev/null || USER_REPLY="N"
    fi
    if [[ "$USER_REPLY" =~ ^[Yy]$ ]]; then
        REMOVE_USERS=true
    fi
    echo ""
fi

echo -e "${CYAN}${BOLD}Starting removal...${NC}"
echo ""

# ═════════════════════════════════════════════════════════════
# Step 1: Stop and disable all services
# ═════════════════════════════════════════════════════════════
info "[1/9] Stopping and disabling services..."

# List of all CodeRed-related service and timer units
UNITS=(
    codered-zeek.service
    codered-suricata.service
    codered-pcap.service
    filebeat.service
    codered-rule-update.timer
    codered-rule-update.service
    codered-update.timer
    codered-update.service
    codered-intel-update.timer
    codered-intel-update.service
    codered-disk-cleanup.timer
    codered-disk-cleanup.service
    codered-disk-resize.service
    codered-firstboot.service
    codered-remove-builder.service
    regenerate-ssh-keys.service
)

for unit in "${UNITS[@]}"; do
    if systemctl list-unit-files "$unit" &>/dev/null 2>&1; then
        systemctl stop "$unit" 2>/dev/null && log "Stopped $unit" || true
        systemctl disable "$unit" 2>/dev/null && log "Disabled $unit" || true
    fi
done

log "All CodeRed services stopped and disabled."

# ═════════════════════════════════════════════════════════════
# Step 2: Remove systemd unit files
# ═════════════════════════════════════════════════════════════
info "[2/9] Removing systemd unit files..."

# Remove all codered-* unit files
for f in /etc/systemd/system/codered-*; do
    if [ -f "$f" ]; then
        rm -f "$f"
        log "Removed $f"
    fi
done

# Remove regenerate-ssh-keys service (created by prepare-ova.sh)
if [ -f /etc/systemd/system/regenerate-ssh-keys.service ]; then
    rm -f /etc/systemd/system/regenerate-ssh-keys.service
    log "Removed regenerate-ssh-keys.service"
fi

# Remove filebeat drop-in override
if [ -d /etc/systemd/system/filebeat.service.d ]; then
    rm -f /etc/systemd/system/filebeat.service.d/codered.conf
    # Remove the directory if empty
    rmdir /etc/systemd/system/filebeat.service.d 2>/dev/null || true
    log "Removed filebeat drop-in override"
fi

log "Systemd units removed."

# ═════════════════════════════════════════════════════════════
# Step 3: Remove NDR software directories
# ═════════════════════════════════════════════════════════════
info "[3/9] Removing NDR software directories..."

# Remove immutable flag from cli.py if set (prepare-ova.sh / update script sets chattr +i)
chattr -i /opt/codered/shell/cli.py 2>/dev/null || true

if [ -d /opt/codered ]; then
    rm -rf /opt/codered
    log "Removed /opt/codered/"
fi

if [ -d /opt/zeek/share/zeek/site/codered-detections ]; then
    rm -rf /opt/zeek/share/zeek/site/codered-detections
    log "Removed /opt/zeek/share/zeek/site/codered-detections/"
fi

if [ -d /opt/zeek/share/zeek/site/intel ]; then
    rm -rf /opt/zeek/share/zeek/site/intel
    log "Removed /opt/zeek/share/zeek/site/intel/"
fi

log "NDR software directories removed."

# ═════════════════════════════════════════════════════════════
# Step 4: Remove configuration files
# ═════════════════════════════════════════════════════════════
info "[4/9] Removing configuration files..."

# /etc/codered/
if [ -d /etc/codered ]; then
    rm -rf /etc/codered
    log "Removed /etc/codered/"
fi

# Sudoers
for f in /etc/sudoers.d/codered-ndr /etc/sudoers.d/codered-admin; do
    if [ -f "$f" ]; then
        rm -f "$f"
        log "Removed $f"
    fi
done

# Logrotate
if [ -f /etc/logrotate.d/codered-ndr ]; then
    rm -f /etc/logrotate.d/codered-ndr
    log "Removed /etc/logrotate.d/codered-ndr"
fi

# CLI command
if [ -f /usr/local/bin/coderedndr ]; then
    rm -f /usr/local/bin/coderedndr
    log "Removed /usr/local/bin/coderedndr"
fi

# Zeek PATH profile
if [ -f /etc/profile.d/zeek-path.sh ]; then
    rm -f /etc/profile.d/zeek-path.sh
    log "Removed /etc/profile.d/zeek-path.sh"
fi

# PAM su restriction
if [ -f /etc/pam.d/su-codered ]; then
    rm -f /etc/pam.d/su-codered
    log "Removed /etc/pam.d/su-codered"
fi

# SSH hardening config (created by prepare-ova.sh)
if [ -f /etc/ssh/sshd_config.d/90-codered-hardening.conf ]; then
    rm -f /etc/ssh/sshd_config.d/90-codered-hardening.conf
    log "Removed /etc/ssh/sshd_config.d/90-codered-hardening.conf"
    # Reload SSH to apply removal
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi

# MOTD banner
if [ -f /etc/update-motd.d/00-codered-banner ]; then
    rm -f /etc/update-motd.d/00-codered-banner
    log "Removed /etc/update-motd.d/00-codered-banner"
    # Re-enable default MOTD scripts
    chmod +x /etc/update-motd.d/* 2>/dev/null || true
    log "Re-enabled default MOTD scripts"
fi

# Netplan default config (only remove the CodeRed-generated default)
if [ -f /etc/netplan/01-codered-default.yaml ]; then
    rm -f /etc/netplan/01-codered-default.yaml
    log "Removed /etc/netplan/01-codered-default.yaml"
fi

# SSH issue.net banner — restore to default
if [ -f /etc/issue.net ] && grep -q "CodeRed" /etc/issue.net 2>/dev/null; then
    echo "Ubuntu $(lsb_release -rs 2>/dev/null || echo '')" > /etc/issue.net
    log "Restored /etc/issue.net to default"
fi

# PAM su modification — remove the pam_wheel.so line if added by prepare-ova.sh
if grep -q "pam_wheel.so group=sudo" /etc/pam.d/su 2>/dev/null; then
    sed -i '/pam_wheel.so group=sudo/d' /etc/pam.d/su
    log "Removed pam_wheel.so restriction from /etc/pam.d/su"
fi

log "Configuration files removed."

# ═════════════════════════════════════════════════════════════
# Step 5: Remove state and marker files
# ═════════════════════════════════════════════════════════════
info "[5/9] Removing state and marker files..."

# /var/lib/codered/
if [ -d /var/lib/codered ]; then
    rm -rf /var/lib/codered
    log "Removed /var/lib/codered/"
fi

log "State files removed."

# ═════════════════════════════════════════════════════════════
# Step 6: Remove log files
# ═════════════════════════════════════════════════════════════
info "[6/9] Removing log files..."

if [ -d /var/log/codered ]; then
    rm -rf /var/log/codered
    log "Removed /var/log/codered/"
fi

log "Log files removed."

# ═════════════════════════════════════════════════════════════
# Step 7: Remove Filebeat CodeRed module configs
# ═════════════════════════════════════════════════════════════
info "[7/9] Cleaning Filebeat module configs..."

for modfile in \
    /etc/filebeat/modules.d/zeek.yml \
    /etc/filebeat/modules.d/zeek.yml.disabled \
    /etc/filebeat/modules.d/suricata.yml \
    /etc/filebeat/modules.d/suricata.yml.disabled; do
    if [ -f "$modfile" ]; then
        rm -f "$modfile"
        log "Removed $modfile"
    fi
done

log "Filebeat modules cleaned."

# ═════════════════════════════════════════════════════════════
# Step 8: Optionally remove data, packages, and users
# ═════════════════════════════════════════════════════════════
info "[8/9] Processing optional removals..."

# --- Data ---
if [ "$REMOVE_DATA" = true ]; then
    if [ -d /nsm ]; then
        rm -rf /nsm
        log "Removed /nsm/ (all network monitoring data deleted)"
    fi
else
    if [ -d /nsm ]; then
        warn "Kept /nsm/ — network monitoring data preserved"
    fi
fi

# --- Packages ---
if [ "$REMOVE_PACKAGES" = true ]; then
    info "Removing Zeek, Suricata, and Filebeat packages..."

    # Stop any running instances first
    systemctl stop zeek 2>/dev/null || true
    systemctl stop suricata 2>/dev/null || true
    systemctl stop filebeat 2>/dev/null || true

    # Remove Zeek
    if dpkg -l zeek 2>/dev/null | grep -q "^ii"; then
        apt-get purge -y zeek 2>/dev/null || true
        log "Removed Zeek package"
    fi
    # Clean up Zeek APT source
    rm -f /etc/apt/sources.list.d/zeek.list
    rm -f /etc/apt/trusted.gpg.d/zeek.gpg
    log "Removed Zeek APT repository"

    # Remove Suricata
    if dpkg -l suricata 2>/dev/null | grep -q "^ii"; then
        apt-get purge -y suricata suricata-update 2>/dev/null || true
        log "Removed Suricata package"
    fi

    # Remove Filebeat
    if dpkg -l filebeat 2>/dev/null | grep -q "^ii"; then
        apt-get purge -y filebeat 2>/dev/null || true
        log "Removed Filebeat package"
    fi
    # Clean up Elastic APT source
    rm -f /etc/apt/sources.list.d/elastic-8.x.list
    rm -f /etc/apt/trusted.gpg.d/elastic.gpg
    log "Removed Elastic APT repository"

    # Autoremove orphaned deps
    apt-get autoremove -y --purge 2>/dev/null || true
    log "Packages removed and cleaned up."
else
    warn "Kept Zeek, Suricata, and Filebeat packages."
    # Even if keeping packages, re-enable their native services so they work standalone
    systemctl unmask suricata 2>/dev/null || true
    systemctl unmask zeek 2>/dev/null || true
    systemctl unmask filebeat 2>/dev/null || true
fi

# --- Users ---
if [ "$REMOVE_USERS" = true ] && [ "$OVA_USERS_EXIST" = true ]; then
    info "Removing OVA users..."
    if id coderedndr &>/dev/null; then
        # Kill any running processes for the user
        pkill -u coderedndr 2>/dev/null || true
        sleep 1
        userdel -r coderedndr 2>/dev/null || true
        rm -rf /home/coderedndr 2>/dev/null || true
        log "Removed user: coderedndr"
    fi
    if id cradmin &>/dev/null; then
        pkill -u cradmin 2>/dev/null || true
        sleep 1
        userdel -r cradmin 2>/dev/null || true
        rm -rf /home/cradmin 2>/dev/null || true
        log "Removed user: cradmin"
    fi
    log "OVA users removed."
elif [ "$OVA_USERS_EXIST" = true ]; then
    warn "Kept OVA users (coderedndr, cradmin)."
fi

# ═════════════════════════════════════════════════════════════
# Step 9: Reload systemd
# ═════════════════════════════════════════════════════════════
info "[9/9] Reloading systemd daemon..."

systemctl daemon-reload
log "Systemd daemon reloaded."

# ═════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "  +----------------------------------------------------------+"
echo "  |     CodeRed NDR has been uninstalled.                    |"
echo "  +----------------------------------------------------------+"
echo -e "${NC}"
echo "  Removed:"
echo "    - All CodeRed systemd services and timers"
echo "    - /opt/codered/ (application files)"
echo "    - /etc/codered/ (configuration)"
echo "    - /var/log/codered/ (logs)"
echo "    - /var/lib/codered/ (state)"
echo "    - Sudoers, logrotate, CLI, MOTD, SSH hardening configs"
echo "    - Filebeat CodeRed module configs"

if [ "$REMOVE_DATA" = true ]; then
    echo "    - /nsm/ (all network monitoring data)"
else
    echo "    - /nsm/ was KEPT (network monitoring data preserved)"
fi

if [ "$REMOVE_PACKAGES" = true ]; then
    echo "    - Zeek, Suricata, Filebeat packages and APT repos"
else
    echo "    - Zeek, Suricata, Filebeat packages were KEPT"
fi

if [ "$REMOVE_USERS" = true ] && [ "$OVA_USERS_EXIST" = true ]; then
    echo "    - OVA users (coderedndr, cradmin) removed"
elif [ "$OVA_USERS_EXIST" = true ]; then
    echo "    - OVA users (coderedndr, cradmin) were KEPT"
fi

echo ""
echo "  Uninstall log saved to: $LOGFILE"
echo ""

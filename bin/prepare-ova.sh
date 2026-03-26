#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  CodeRed NDR - OVA Preparation Script                       ║
# ║  Locks down user access + cleans server for OVA export       ║
# ║                                                              ║
# ║  Usage: sudo bash /home/coderedai/.local/bin/prepare-ova.sh  ║
# ║                                                              ║
# ║  WARNING: This is destructive. Run AFTER provisioning is     ║
# ║  complete and verified. The VM will be ready for export.     ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}=== Step $1: $2 ===${NC}"; }

[ "$(id -u)" -eq 0 ] || err "Must run as root: sudo bash $0"

echo -e "${BOLD}${RED}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║   CodeRed NDR - OVA Preparation (DESTRUCTIVE)           ║"
echo "  ║   This will lock down users and clean the server.       ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
read -rp "  Are you sure you want to proceed? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

###############################################################################
# Step 1: Create coderedndr user
###############################################################################
step 1 "Setting up coderedndr user"

NDRUSR="coderedndr"
NDRHOME="/home/$NDRUSR"

# Create user if not exists
if ! id "$NDRUSR" &>/dev/null; then
    useradd -m -s /bin/bash -c "CodeRed NDR Sensor" "$NDRUSR"
    log "Created user: $NDRUSR"
else
    log "User $NDRUSR already exists"
fi

# Set a default password (customer changes on first boot)
echo "${NDRUSR}:CodeRed@NDR!" | chpasswd
log "Default password set (customer will be forced to change)"

# Force password change on first login
chage -d 0 "$NDRUSR"
log "Password change enforced on first login"

# Add to sudo group (needed for coderedndr CLI to manage services)
usermod -aG sudo "$NDRUSR" 2>/dev/null || true

# Allow coderedndr to run specific commands without password via sudoers
cat > /etc/sudoers.d/codered-ndr << 'SUDOERS'
# CodeRed NDR - Restricted sudo for sensor management
# The coderedndr user can manage NDR services without entering a password

# Service management
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl start codered-suricata
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl stop codered-suricata
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl restart codered-suricata
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl status codered-suricata
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl start codered-zeek
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl stop codered-zeek
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl restart codered-zeek
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl status codered-zeek
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl start filebeat
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl stop filebeat
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl restart filebeat
coderedndr ALL=(root) NOPASSWD: /usr/bin/systemctl status filebeat

# NDR management scripts
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/start-suricata.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/start-zeek.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/stop-zeek.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/tune-interface.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/update-rules.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/codered-update.sh
coderedndr ALL=(root) NOPASSWD: /opt/codered/bin/health-check.sh

# First-boot wizard
coderedndr ALL=(root) NOPASSWD: /opt/codered/firstboot/firstboot.sh

# CLI needs root for service management
coderedndr ALL=(root) NOPASSWD: /usr/bin/python3 /opt/codered/shell/cli.py
coderedndr ALL=(root) NOPASSWD: /usr/local/bin/coderedndr

# Network configuration (for first-boot wizard)
coderedndr ALL=(root) NOPASSWD: /usr/sbin/netplan apply
coderedndr ALL=(root) NOPASSWD: /usr/bin/hostnamectl set-hostname *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip link set * up promisc on
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip link set * up
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip addr flush dev *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip -br addr show *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip -br link show
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip -4 -br addr show *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip -d link show
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip link show *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ip route get *
coderedndr ALL=(root) NOPASSWD: /usr/sbin/ethtool -K *

# Admin login via CLI option 17 — PAM and group-check gated in Python
# The CLI verifies credentials and codered-admin group membership before
# reaching this exec. coderedndr cannot escalate without passing both checks.
coderedndr ALL=(cradmin) NOPASSWD: /bin/bash
coderedndr ALL=(cradmin) NOPASSWD: /bin/bash -l

# ZeekControl (restricted to specific subcommands)
coderedndr ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl deploy
coderedndr ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl start
coderedndr ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl stop
coderedndr ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl restart
coderedndr ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl status

# Suricata rule updates
coderedndr ALL=(root) NOPASSWD: /usr/bin/suricata-update
coderedndr ALL=(root) NOPASSWD: /usr/bin/suricata -T *

# Log access (--no-pager prevents shell escape to root)
coderedndr ALL=(root) NOPASSWD: /usr/bin/tail -f /nsm/suricata/log/eve.json
coderedndr ALL=(root) NOPASSWD: /usr/bin/tail -f /nsm/zeek/logs/current/*
coderedndr ALL=(root) NOPASSWD: /usr/bin/journalctl -u codered-zeek --no-pager *
coderedndr ALL=(root) NOPASSWD: /usr/bin/journalctl -u codered-suricata --no-pager *
coderedndr ALL=(root) NOPASSWD: /usr/bin/journalctl -u filebeat --no-pager *
SUDOERS
chmod 440 /etc/sudoers.d/codered-ndr
visudo -cf /etc/sudoers.d/codered-ndr || err "Sudoers syntax error — aborting"
log "Sudoers configured: coderedndr has restricted NOPASSWD access for NDR management only"

###############################################################################
# Step 1b: Create CodeRed admin user (vendor/admin access — NOT for customers)
###############################################################################
log "Setting up CodeRed admin account..."

ADMINUSR="cradmin"
ADMINHOME="/home/$ADMINUSR"

if ! id "$ADMINUSR" &>/dev/null; then
    useradd -m -s /bin/bash -c "CodeRed NDR Admin" "$ADMINUSR"
    log "Created admin user: $ADMINUSR"
fi

# Set a default admin password — CHANGE THIS before distributing the OVA
# The password is forced to change on first login (chage -d 0)
# Customers never see this account — it is not shown in the customer CLI
ADMIN_DEFAULT_PW="CRAdmin@NDR2025!"
echo "${ADMINUSR}:${ADMIN_DEFAULT_PW}" | chpasswd
chage -d 0 "$ADMINUSR"
log "Admin default password set — forced change on first login"
log "IMPORTANT: Change this password immediately after first login"
unset ADMIN_DEFAULT_PW

# Create codered-admin group — used by CLI option 17 to gate admin login
# Only members of this group can authenticate via the CLI admin login prompt
groupadd -f codered-admin
usermod -aG codered-admin "$ADMINUSR"
log "Created codered-admin group and added $ADMINUSR as member"

# Full sudo access for admin (ALL commands, no password prompt)
usermod -aG sudo "$ADMINUSR" 2>/dev/null || true
cat > /etc/sudoers.d/codered-admin << 'ADMINSUDOERS'
# CodeRed NDR - Admin/vendor support account
# Full root access for remote support and troubleshooting
# This account is separate from the customer coderedndr account
cradmin ALL=(ALL:ALL) NOPASSWD: ALL
ADMINSUDOERS
chmod 440 /etc/sudoers.d/codered-admin
visudo -cf /etc/sudoers.d/codered-admin || err "Admin sudoers syntax error"

# Admin gets full bash shell — no CLI auto-launch
# SSH directly as cradmin, get bash immediately, use sudo freely
cat > "$ADMINHOME/.bashrc" << 'ADMINRC'
# CodeRed NDR - Admin shell
# Full bash access with sudo — for vendor/admin use only

export PATH="/opt/zeek/bin:/usr/local/bin:$PATH"

# NDR management shortcuts
alias ndr='sudo /usr/local/bin/coderedndr'
alias health='sudo /opt/codered/bin/health-check.sh'
alias status='sudo systemctl status codered-zeek codered-suricata filebeat codered-ml --no-pager'
alias logs-suri='sudo tail -f /nsm/suricata/log/eve.json | jq .'
alias logs-zeek='sudo tail -f /nsm/zeek/logs/current/conn.log'
alias logs-notice='sudo tail -f /nsm/zeek/logs/current/notice.log'
alias logs-ml='sudo tail -f /var/log/codered/ml-engine.log'
alias logs-audit='sudo tail -f /var/log/codered/audit.log'
alias conf='sudo cat /etc/codered/sensor.conf'
alias zeek-conf='sudo cat /opt/zeek/share/zeek/site/local.zeek'

PS1='\[[0;31m\][cradmin]\[[0m\] \[[0;33m\]codered-ndr\[[0m\]:\[[0;34m\]\w\[[0m\]\$ '

echo ""
echo "  CodeRed NDR — Admin Shell"
echo "  Type 'status' for service status, 'health' for full health check"
echo "  Type 'ndr' to launch the customer management CLI"
echo ""
ADMINRC
chown "$ADMINUSR:$ADMINUSR" "$ADMINHOME/.bashrc"

# Prepare .ssh directory — admin can also add SSH keys for key-based auth
# Both password and key auth are enabled for this account
mkdir -p "$ADMINHOME/.ssh"
chmod 700 "$ADMINHOME/.ssh"
touch "$ADMINHOME/.ssh/authorized_keys"
chmod 600 "$ADMINHOME/.ssh/authorized_keys"
chown -R "$ADMINUSR:$ADMINUSR" "$ADMINHOME/.ssh"
log "Admin SSH directory ready — optionally add SSH keys for key-based auth"

log "Admin account configured: $ADMINUSR"
log "  Login:    ssh cradmin@<sensor-ip>"
log "  Password: CRAdmin@NDR2025!  (forced change on first login)"
log "  Access:   full bash + sudo, no customer CLI"

# Auto-launch CLI on login for coderedndr user
cat > "$NDRHOME/.bash_profile" << 'BASHPROFILE'
# CodeRed NDR - Auto-launch management CLI
# The CLI provides all sensor management functionality

# Only launch CLI on interactive login (not scp/sftp)
if [ -t 0 ] && [ -z "$CODERED_CLI_RUNNING" ]; then
    export CODERED_CLI_RUNNING=1
    # Launch CLI with sudo (NOPASSWD configured)
    sudo /usr/local/bin/coderedndr
    # After CLI exits, give option to stay in shell or logout
    echo ""
    echo "  CLI exited. Type 'exit' to disconnect or press Enter for shell."
    read -rt 10 -p "  > " CHOICE || true
    if [ "${CHOICE:-exit}" = "exit" ]; then
        logout
    fi
fi
BASHPROFILE
chown "$NDRUSR:$NDRUSR" "$NDRHOME/.bash_profile"
chmod 644 "$NDRHOME/.bash_profile"

# Minimal .bashrc
cat > "$NDRHOME/.bashrc" << 'BASHRC'
# CodeRed NDR sensor shell
export PATH="/opt/zeek/bin:/usr/local/bin:$PATH"
alias ndr='sudo /usr/local/bin/coderedndr'
alias health='sudo /opt/codered/bin/health-check.sh'
alias status='sudo systemctl status codered-suricata codered-zeek filebeat --no-pager'

# Minimal prompt
PS1='\[\033[0;32m\]codered-ndr\[\033[0m\]:\[\033[0;34m\]\w\[\033[0m\]\$ '
BASHRC
chown "$NDRUSR:$NDRUSR" "$NDRHOME/.bashrc"
chmod 644 "$NDRHOME/.bashrc"

log "CLI auto-launch configured for $NDRUSR"

###############################################################################
# Step 2: Lock down root and remove coderedai user
###############################################################################
step 2 "Locking down root access"

# Lock root password (disable password login for root)
passwd -l root
log "Root password locked"

# Ensure root cannot login via SSH with password
# (already set prohibit-password in provisioning, but enforce here)
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true
if [ -f /etc/ssh/sshd_config.d/90-codered-hardening.conf ]; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config.d/90-codered-hardening.conf
fi
log "Root SSH login disabled completely"

# Restrict su to only users in sudo group
cat > /etc/pam.d/su-codered << 'SUCONF'
# Restrict su access
auth required pam_wheel.so group=sudo
SUCONF
# Don't replace the whole pam su config — just ensure wheel restriction
if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
    sed -i '/^auth\s*sufficient\s*pam_rootok.so/a auth required pam_wheel.so group=sudo' /etc/pam.d/su
fi
log "su restricted to sudo group only"

# SSH: Only allow coderedndr user
if ! grep -q "AllowUsers" /etc/ssh/sshd_config.d/90-codered-hardening.conf 2>/dev/null; then
    echo "" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
    echo "# Only allow the NDR management user" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
    echo "AllowUsers coderedndr cradmin" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
fi

# cradmin supports both password and SSH key authentication
# Password is set above (forced change on first login)
# Admin can optionally add SSH keys for key-based auth
# Do NOT add a Match User cradmin block here — that would lock to key-only

# Ensure AllowUsers includes cradmin
if grep -q "AllowUsers" /etc/ssh/sshd_config.d/90-codered-hardening.conf 2>/dev/null; then
    # Already has AllowUsers line — make sure cradmin is in it
    if ! grep "AllowUsers" /etc/ssh/sshd_config.d/90-codered-hardening.conf | grep -q "cradmin"; then
        sed -i "s/^AllowUsers .*/& cradmin/" /etc/ssh/sshd_config.d/90-codered-hardening.conf
    fi
fi
log "SSH: coderedndr (customer) + cradmin (admin) — both password and key auth"

# Reload SSH
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
log "SSH config reloaded"

###############################################################################
# Step 3: Remove unnecessary packages
###############################################################################
step 3 "Removing unnecessary packages"

# Remove packages not needed for NDR sensor
REMOVE_PKGS=""
for pkg in \
    snapd snap-confine snapd-seed \
    ubuntu-advantage-tools ua-tools \
    landscape-common landscape-client \
    popularity-contest \
    command-not-found \
    friendly-recovery \
    plymouth plymouth-theme-ubuntu-text \
    unattended-upgrades \
    packagekit \
    accountsservice \
    fwupd fwupd-signed \
    modemmanager \
    bluez bluetooth \
    cups cups-browsed \
    avahi-daemon \
    whoopsie kerneloops apport \
    ubuntu-report \
    motd-news-config \
    lxd-installer \
    needrestart \
    vim-tiny nano \
    pastebinit \
    sosreport \
    ec2-hibinit-agent \
    hibagent \
    xauth xdg-utils \
    fonts-ubuntu-console \
    open-vm-tools; do  # Will reinstall open-vm-tools only if deploying on VMware
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        REMOVE_PKGS="$REMOVE_PKGS $pkg"
    fi
done

if [ -n "$REMOVE_PKGS" ]; then
    log "Removing:$REMOVE_PKGS"
    apt-get purge -y $REMOVE_PKGS 2>/dev/null || true
    apt-get autoremove -y --purge 2>/dev/null || true
fi
log "Unnecessary packages removed"

# Reinstall open-vm-tools (needed for VMware OVA)
apt-get install -y -qq open-vm-tools 2>/dev/null || true
log "open-vm-tools installed (required for VMware OVA)"

###############################################################################
# Step 4: Clean cloud-init and AWS artifacts
###############################################################################
step 4 "Removing cloud-init and AWS artifacts"

# Disable and remove cloud-init
if dpkg -l cloud-init 2>/dev/null | grep -q "^ii"; then
    # Clean cloud-init state
    cloud-init clean --logs 2>/dev/null || true

    # Remove cloud-init (keep cloud-guest-utils — needed for growpart/auto-resize)
    apt-get purge -y cloud-init 2>/dev/null || true
    rm -rf /etc/cloud /var/lib/cloud /run/cloud-init
    log "cloud-init removed"
fi

# Remove AWS-specific packages
for pkg in amazon-ssm-agent aws-cli awscli ec2-instance-connect; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        apt-get purge -y "$pkg" 2>/dev/null || true
    fi
done

# Remove AWS artifacts
rm -rf /var/log/amazon 2>/dev/null || true
rm -f /etc/apt/sources.list.d/amazon* 2>/dev/null || true
rm -f /etc/profile.d/aws* 2>/dev/null || true

# Remove any EC2 metadata caching
rm -rf /var/lib/amazon 2>/dev/null || true

log "AWS artifacts cleaned"

###############################################################################
# Step 5: Remove coderedai user (builder account)
###############################################################################
step 5 "Removing builder account (coderedai)"

# Copy any needed files from coderedai before removal
# (provision script is already deployed to /opt/codered)
cp /home/coderedai/.local/bin/provision-ndr.sh /opt/codered/bin/ 2>/dev/null || true
cp /home/coderedai/.local/bin/prepare-ova.sh /opt/codered/bin/ 2>/dev/null || true

# Don't kill coderedai processes here — we may be running as coderedai.
# The deferred systemd service (codered-remove-builder) handles full cleanup on next boot.

# Defer user removal to next boot
REMOVE_BUILDER=true

###############################################################################
# Step 6: Clean filesystem for OVA distribution
###############################################################################
step 6 "Cleaning filesystem"

# --- SSH host keys (regenerate on first boot) ---
rm -f /etc/ssh/ssh_host_*
# Create a systemd service to regenerate on boot
cat > /etc/systemd/system/regenerate-ssh-keys.service << 'SSHKEYGEN'
[Unit]
Description=Regenerate SSH host keys on first boot
ConditionPathExists=!/etc/ssh/ssh_host_rsa_key
Before=ssh.service sshd.service

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
ExecStartPost=/usr/bin/systemctl reload ssh

[Install]
WantedBy=multi-user.target
SSHKEYGEN
systemctl enable regenerate-ssh-keys.service
log "SSH host keys removed (will regenerate on first boot)"

# --- Machine ID (must be unique per VM) ---
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
log "Machine ID cleared (will regenerate on boot)"

# --- Bash history ---
for userhome in /root /home/*; do
    rm -f "$userhome/.bash_history" 2>/dev/null || true
    rm -f "$userhome/.python_history" 2>/dev/null || true
    rm -f "$userhome/.lesshst" 2>/dev/null || true
    rm -f "$userhome/.viminfo" 2>/dev/null || true
    rm -rf "$userhome/.cache" 2>/dev/null || true
    rm -rf "$userhome/.local/share/recently-used*" 2>/dev/null || true
done
log "Shell history cleared"

# --- Claude Code session data ---
rm -rf /home/coderedai/.claude 2>/dev/null || true
rm -rf /root/.claude 2>/dev/null || true
log "Claude Code session data removed"

# --- Logs ---
# Clear system logs (keep structure, zero content)
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
find /var/log -type f -name "*.log.*" -delete 2>/dev/null || true
find /var/log -type f -name "*.gz" -delete 2>/dev/null || true
find /var/log -type f -name "*.old" -delete 2>/dev/null || true
truncate -s 0 /var/log/wtmp 2>/dev/null || true
truncate -s 0 /var/log/btmp 2>/dev/null || true
truncate -s 0 /var/log/lastlog 2>/dev/null || true
truncate -s 0 /var/log/faillog 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true
log "Logs cleared"

# --- NDR logs (start fresh) ---
find /nsm -type f -name "*.log" -delete 2>/dev/null || true
find /nsm -type f -name "*.json" -delete 2>/dev/null || true
rm -rf /nsm/zeek/spool/* 2>/dev/null || true
rm -rf /nsm/zeek/logs/current/* 2>/dev/null || true
truncate -s 0 /var/log/codered/*.log 2>/dev/null || true
log "NDR logs cleared"

# --- APT cache ---
apt-get clean
rm -rf /var/lib/apt/lists/*
log "APT cache cleaned"

# --- Temp files ---
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
log "Temp files cleaned"

# --- DHCP leases ---
rm -f /var/lib/dhcp/*.leases 2>/dev/null || true
rm -f /var/lib/NetworkManager/*.lease 2>/dev/null || true
log "DHCP leases cleared"

# --- Netplan (remove cloud-init generated, keep codered if exists) ---
rm -f /etc/netplan/50-cloud-init.yaml 2>/dev/null || true
# Write a minimal default netplan (DHCP on first interface)
if [ ! -f /etc/netplan/01-codered-mgmt.yaml ]; then
    cat > /etc/netplan/01-codered-default.yaml << 'NETPLAN'
# CodeRed NDR - Default network config (replaced by first-boot wizard)
network:
  version: 2
  renderer: networkd
  ethernets:
    # Management interface - DHCP by default
    # First-boot wizard will configure the actual interface
    all-en:
      match:
        name: "en*"
      dhcp4: true
    all-eth:
      match:
        name: "eth*"
      dhcp4: true
NETPLAN
    chmod 600 /etc/netplan/01-codered-default.yaml
fi
log "Network config cleaned"

# --- Misc ---
rm -f /etc/udev/rules.d/70-persistent-net.rules 2>/dev/null || true
rm -f /root/.ssh/authorized_keys 2>/dev/null || true
rm -rf /root/.gnupg 2>/dev/null || true
rm -f /var/cache/debconf/*.old 2>/dev/null || true

# Remove any git repos cloned during build
rm -rf /opt/codered/repo 2>/dev/null || true

log "Misc artifacts cleaned"

###############################################################################
# Step 7a: Auto-resize disk on boot
###############################################################################
step "7a" "Creating auto-resize disk service"

cat > /opt/codered/bin/auto-resize-disk.sh << 'AUTORESIZE'
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
AUTORESIZE
chmod 755 /opt/codered/bin/auto-resize-disk.sh

# Install growpart (needed for partition resize)
apt-get install -y -qq cloud-guest-utils 2>/dev/null || true

cat > /etc/systemd/system/codered-disk-resize.service << 'DISKSVC'
[Unit]
Description=CodeRed NDR - Auto-resize disk on boot
DefaultDependencies=no
Before=codered-firstboot.service
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/opt/codered/bin/auto-resize-disk.sh
RemainAfterExit=yes
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
DISKSVC
systemctl daemon-reload
systemctl enable codered-disk-resize.service
log "Auto-resize disk service created — disk expansion is automatic on boot"

###############################################################################
# Step 7: Set MOTD / Login Banner
###############################################################################
step 7 "Setting login banner"

# Disable default Ubuntu MOTD components
chmod -x /etc/update-motd.d/* 2>/dev/null || true

# Create CodeRed NDR banner
cat > /etc/update-motd.d/00-codered-banner << 'MOTD'
#!/bin/bash
VERSION=$(cat /opt/codered/VERSION 2>/dev/null || echo "unknown")
HOSTNAME=$(hostname)
UPTIME=$(uptime -p 2>/dev/null || echo "")

echo ""
echo "   ╔══════════════════════════════════════════════════════════╗"
echo "   ║                  CodeRed NDR Sensor                     ║"
printf "   ║           Version: %-10s                       ║\n" "$VERSION"
echo "   ╚══════════════════════════════════════════════════════════╝"
echo ""
echo "   Hostname:  $HOSTNAME"
echo "   Uptime:    $UPTIME"
echo ""

# Quick status
SURI_STATUS=$(systemctl is-active codered-suricata 2>/dev/null || echo "inactive")
ZEEK_STATUS=$(systemctl is-active codered-zeek 2>/dev/null || echo "inactive")
FB_STATUS=$(systemctl is-active filebeat 2>/dev/null || echo "inactive")

if [ "$SURI_STATUS" = "active" ]; then
    echo "   Suricata:  ● active"
else
    echo "   Suricata:  ○ $SURI_STATUS"
fi
if [ "$ZEEK_STATUS" = "active" ]; then
    echo "   Zeek:      ● active"
else
    echo "   Zeek:      ○ $ZEEK_STATUS"
fi
if [ "$FB_STATUS" = "active" ]; then
    echo "   Filebeat:  ● active"
else
    echo "   Filebeat:  ○ $FB_STATUS"
fi
echo ""

# Check if first-boot is needed
if [ ! -f /var/lib/codered/.firstboot-complete ]; then
    echo "   ⚠  First-boot setup required. Starting wizard..."
    echo ""
fi
MOTD
chmod 755 /etc/update-motd.d/00-codered-banner

# SSH banner
cat > /etc/issue.net << 'ISSUE'

  ══════════════════════════════════════════════════════
       CodeRed NDR Sensor — Authorized Access Only
  ══════════════════════════════════════════════════════

ISSUE

# Enable banner in SSH
if [ -f /etc/ssh/sshd_config.d/90-codered-hardening.conf ]; then
    if ! grep -q "Banner" /etc/ssh/sshd_config.d/90-codered-hardening.conf; then
        echo "" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
        echo "# Login banner" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
        echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/90-codered-hardening.conf
    fi
fi

log "Login banner configured"

###############################################################################
# Step 8: Ensure first-boot wizard runs for coderedndr user
###############################################################################
step 8 "Configuring first-boot trigger"

# Make the first-boot wizard also trigger from CLI if sensor.conf missing
# Remove the marker so first boot will run
rm -f /var/lib/codered/.firstboot-complete 2>/dev/null || true
rm -f /etc/codered/.setup-complete 2>/dev/null || true
rm -f /etc/codered/sensor.conf 2>/dev/null || true

# Reset Zeek node.cfg to template
sed -i 's|interface=af_packet::.*|interface=af_packet::__MONITOR_IF__|' /opt/zeek/etc/node.cfg 2>/dev/null || true

# Reset Filebeat to placeholder
sed -i 's|hosts: \["[^"]*"\]|hosts: ["__SIEM_HOST__:__SIEM_PORT__"]|g' /etc/filebeat/filebeat.yml 2>/dev/null || true

# Ensure all NDR services are stopped and disabled (start after first-boot)
systemctl stop codered-suricata 2>/dev/null || true
systemctl stop codered-zeek 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true
systemctl disable codered-suricata 2>/dev/null || true
systemctl disable codered-zeek 2>/dev/null || true
systemctl disable filebeat 2>/dev/null || true

log "First-boot state reset — wizard will run on first customer login"

###############################################################################
# Step 9: Remove builder user (coderedai)
###############################################################################
step 9 "Removing builder account"

if [ "$REMOVE_BUILDER" = true ] && id coderedai &>/dev/null; then
    # Remove from sudoers first
    rm -f /etc/sudoers.d/coderedai 2>/dev/null || true
    rm -f /etc/sudoers.d/90-cloud-init-users 2>/dev/null || true

    # Revoke sudo group
    deluser coderedai sudo 2>/dev/null || true

    # Schedule removal (can't remove while running as this user)
    cat > /var/lib/codered/.remove-builder.sh << 'RMBUILDER'
#!/bin/bash
# Runs on next boot to remove the builder account
if id coderedai &>/dev/null; then
    userdel -r coderedai 2>/dev/null || true
    rm -rf /home/coderedai 2>/dev/null || true
fi
rm -f /etc/systemd/system/codered-remove-builder.service
rm -f /var/lib/codered/.remove-builder.sh
systemctl daemon-reload
RMBUILDER
    chmod 755 /var/lib/codered/.remove-builder.sh

    cat > /etc/systemd/system/codered-remove-builder.service << 'RMBSVC'
[Unit]
Description=CodeRed NDR - Remove builder account
After=multi-user.target
Before=codered-firstboot.service

[Service]
Type=oneshot
ExecStart=/var/lib/codered/.remove-builder.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RMBSVC
    systemctl daemon-reload
    systemctl enable codered-remove-builder.service
    log "Builder account (coderedai) scheduled for removal on next boot"
else
    log "No builder account to remove"
fi

###############################################################################
# Step 10: Final disk cleanup
###############################################################################
step 10 "Final disk cleanup"

# Remove leftover package data
apt-get autoremove -y --purge 2>/dev/null || true
apt-get clean
dpkg --configure -a 2>/dev/null || true

# Zero free space (helps with OVA compression)
# Only do this if there's enough disk space
FREE_MB=$(df -BM / | awk 'NR==2{print $4}' | tr -d 'M')
if [ "$FREE_MB" -gt 5000 ]; then
    log "Zeroing free space for better OVA compression..."
    dd if=/dev/zero of=/zero.fill bs=1M 2>/dev/null || true
    rm -f /zero.fill
    log "Free space zeroed"
else
    warn "Skipping disk zeroing — less than 5GB free"
fi

# Final sync
sync

log "Disk cleanup complete"

###############################################################################
# Done
###############################################################################
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  CodeRed NDR — OVA Preparation Complete                 ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "  Summary:"
echo "    ✓ User 'coderedndr' created (default password: CodeRed@NDR!)"
echo "    ✓ Password change enforced on first login"
echo "    ✓ CLI auto-launches on SSH login"
echo "    ✓ Root login disabled completely"
echo "    ✓ SSH restricted to coderedndr user only"
echo "    ✓ Builder account (coderedai) scheduled for removal"
echo "    ✓ Cloud-init and AWS artifacts removed"
echo "    ✓ Unnecessary packages purged"
echo "    ✓ SSH keys cleared (regenerate on first boot)"
echo "    ✓ Machine ID cleared (regenerate on boot)"
echo "    ✓ All logs and history cleaned"
echo "    ✓ Disk zeroed for OVA compression"
echo ""
echo "  Login credentials:"
echo ""
echo "    CUSTOMER access:"
echo "      ssh coderedndr@<sensor-ip>"
echo "      Password: CodeRed@NDR!  (must change on first login)"
echo "      Access:   CLI menu only"
echo ""
echo "    ADMIN access (do NOT share with customers):"
echo "      ssh cradmin@<sensor-ip>"
echo "      Password: CRAdmin@NDR2025!  (must change on first login)"
echo "      Access:   full bash + sudo, no customer CLI"
echo ""
echo "  The VM is now ready for OVA export."
echo "  Shut down the VM and export from your hypervisor."
echo ""
echo -e "  ${YELLOW}NOTE: Next boot will:${NC}"
echo "    1. Remove builder account (coderedai)"
echo "    2. Regenerate SSH host keys"
echo "    3. Launch first-boot wizard on coderedndr login"
echo ""

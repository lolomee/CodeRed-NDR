#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║         CodeRed NDR - One-Line Software Installer        ║
# ║                                                          ║
# ║  Usage:                                                  ║
# ║  curl -sSL https://raw.githubusercontent.com/            ║
# ║    lolomee/CodeRed-NDR/main/install.sh | sudo bash       ║
# ╚══════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CODERED_VERSION="1.0.0"
CODERED_REPO="https://github.com/lolomee/CodeRed-NDR.git"
CODERED_DIR="/opt/codered"
CODERED_SRC="/tmp/codered-ndr-install"

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}[$1/6]${NC} ${BOLD}$2${NC}"; }

# ─── Pre-flight Checks ──────────────────────────

echo ""
echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║              CodeRed NDR - Software Installer            ║"
echo "  ║              Version ${CODERED_VERSION}                              ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Must be root
[ "$(id -u)" -eq 0 ] || err "This script must be run as root. Use: curl ... | sudo bash"

# Check OS
if [ ! -f /etc/os-release ]; then
    err "Cannot detect OS. Only Ubuntu 22.04/24.04 is supported."
fi

. /etc/os-release
if [ "$ID" != "ubuntu" ]; then
    err "Unsupported OS: $ID. Only Ubuntu is supported."
fi

UBUNTU_VER="$VERSION_ID"
if [[ "$UBUNTU_VER" != "22.04" && "$UBUNTU_VER" != "24.04" ]]; then
    warn "Ubuntu $UBUNTU_VER detected. Tested on 22.04 and 24.04. Continuing anyway..."
fi

# Check architecture
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    err "Unsupported architecture: $ARCH. Only amd64 is supported."
fi

# Check minimum resources
MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_COUNT=$(nproc)
DISK_GB=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')

echo "  System: Ubuntu ${UBUNTU_VER} (${ARCH})"
echo "  CPU: ${CPU_COUNT} cores | RAM: ${MEM_MB} MB | Disk: ${DISK_GB} GB free"
echo ""

if [ "$MEM_MB" -lt 4000 ]; then
    warn "Low memory (${MEM_MB} MB). Minimum 4 GB recommended."
fi
if [ "$CPU_COUNT" -lt 2 ]; then
    warn "Low CPU (${CPU_COUNT} cores). Minimum 2 cores recommended."
fi
if [ "$DISK_GB" -lt 20 ]; then
    err "Insufficient disk space (${DISK_GB} GB). Minimum 20 GB required."
fi

# Check if already installed
if [ -f "$CODERED_DIR/VERSION" ]; then
    EXISTING_VER=$(cat "$CODERED_DIR/VERSION")
    warn "CodeRed NDR v${EXISTING_VER} is already installed."
    echo ""
    read -p "  Reinstall/upgrade? (y/N): " REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "  Cancelled."
        exit 0
    fi
fi

# ─── Step 1: Install Dependencies ────────────────

step 1 "Installing dependencies..."

apt-get update -qq
apt-get install -y -qq \
    curl \
    gnupg \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    lsb-release \
    python3 \
    dialog \
    ethtool \
    net-tools \
    jq \
    git \
    ufw \
    apparmor \
    apparmor-utils \
    fail2ban \
    tcpdump \
    open-vm-tools \
    logrotate \
    2>/dev/null || true

log "Dependencies installed."

# ─── Step 2: Install Zeek ────────────────────────

step 2 "Installing Zeek..."

if command -v zeek &>/dev/null || [ -x /opt/zeek/bin/zeek ]; then
    log "Zeek already installed: $(/opt/zeek/bin/zeek --version 2>/dev/null || zeek --version 2>/dev/null || echo 'found')"
else
    # Try OBS repo
    ZEEK_INSTALLED=false

    # Method 1: OBS repo for current Ubuntu version
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}/ /" \
        > /etc/apt/sources.list.d/zeek.list 2>/dev/null
    curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}/Release.key" \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg 2>/dev/null || true
    apt-get update -qq 2>/dev/null

    if apt-get install -y -qq zeek 2>/dev/null; then
        ZEEK_INSTALLED=true
    fi

    # Method 2: Try 22.04 repo on 24.04
    if [ "$ZEEK_INSTALLED" = false ] && [ "$UBUNTU_VER" = "24.04" ]; then
        rm -f /etc/apt/sources.list.d/zeek.list
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
            > /etc/apt/sources.list.d/zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key" \
            | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg 2>/dev/null || true
        apt-get update -qq 2>/dev/null
        if apt-get install -y -qq zeek 2>/dev/null; then
            ZEEK_INSTALLED=true
        fi
    fi

    # Method 3: Build from source
    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Package install failed. Building Zeek from source (10-20 min)..."
        apt-get install -y -qq cmake make gcc g++ flex bison libpcap-dev libssl-dev \
            python3-dev swig zlib1g-dev libmaxminddb-dev 2>/dev/null || true

        ZEEK_VERSION="7.0.4"
        cd /tmp
        curl -fsSL -o "zeek-${ZEEK_VERSION}.tar.gz" \
            "https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz" 2>/dev/null || \
        curl -fsSL -o "zeek-${ZEEK_VERSION}.tar.gz" \
            "https://github.com/zeek/zeek/releases/download/v${ZEEK_VERSION}/zeek-${ZEEK_VERSION}.tar.gz" 2>/dev/null

        if [ -f "zeek-${ZEEK_VERSION}.tar.gz" ]; then
            tar xzf "zeek-${ZEEK_VERSION}.tar.gz"
            cd "zeek-${ZEEK_VERSION}"
            ./configure --prefix=/opt/zeek --disable-broker-tests
            make -j$(nproc)
            make install
            cd /tmp
            rm -rf "zeek-${ZEEK_VERSION}" "zeek-${ZEEK_VERSION}.tar.gz"
            ZEEK_INSTALLED=true
        fi
    fi

    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Zeek installation failed. Install manually after setup."
    fi
fi

# Zeek PATH
echo 'export PATH=/opt/zeek/bin:$PATH' > /etc/profile.d/zeek-path.sh
export PATH=/opt/zeek/bin:$PATH

# Don't autostart
systemctl disable zeek 2>/dev/null || true
systemctl stop zeek 2>/dev/null || true

if [ -x /opt/zeek/bin/zeek ]; then
    log "Zeek installed: $(/opt/zeek/bin/zeek --version 2>/dev/null)"
fi

# ─── Step 3: Install Suricata + Filebeat ─────────

step 3 "Installing Suricata and Filebeat..."

# Suricata
if ! command -v suricata &>/dev/null; then
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    apt-get update -qq
    apt-get install -y -o Dpkg::Options::="--force-overwrite" suricata suricata-update 2>/dev/null || \
    apt-get install -y suricata 2>/dev/null || true
fi

systemctl disable suricata 2>/dev/null || true
systemctl stop suricata 2>/dev/null || true

if command -v suricata &>/dev/null; then
    # Enable community-id
    sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml 2>/dev/null || true
    log "Suricata installed: $(suricata -V 2>&1 | head -1)"
else
    warn "Suricata installation failed. Install manually."
fi

# Filebeat
if ! command -v filebeat &>/dev/null; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg 2>/dev/null || true
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update -qq
    apt-get install -y -qq filebeat 2>/dev/null || true
fi

systemctl disable filebeat 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true

if command -v filebeat &>/dev/null; then
    log "Filebeat installed: $(filebeat version 2>/dev/null | head -1)"
else
    warn "Filebeat installation failed. Install manually."
fi

# ─── Step 4: Install CodeRed NDR ─────────────────

step 4 "Installing CodeRed NDR management CLI..."

# Clone repo
rm -rf "$CODERED_SRC"
if git clone --depth 1 "$CODERED_REPO" "$CODERED_SRC" 2>/dev/null; then
    log "Downloaded CodeRed NDR from GitHub."
else
    err "Failed to clone CodeRed NDR repo. Check internet connection."
fi

# Create directories
mkdir -p "$CODERED_DIR"/{shell,bin,firstboot}
mkdir -p /etc/codered
mkdir -p /var/log/codered
mkdir -p /nsm/{zeek/logs/current,suricata,pcap}

# Install files
cp "$CODERED_SRC/shell/cli.py" "$CODERED_DIR/shell/cli.py"
chmod 755 "$CODERED_DIR/shell/cli.py"

cp "$CODERED_SRC/conf/codered.defaults" /etc/codered/codered.defaults
chmod 644 /etc/codered/codered.defaults

echo "$CODERED_VERSION" > "$CODERED_DIR/VERSION"

# Rule update script
cat > "$CODERED_DIR/bin/update-rules.sh" << 'RULESCRIPT'
#!/bin/bash
set -euo pipefail
LOG="/var/log/codered/rule-update.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RULES_DIR="/etc/suricata/rules"
ET_URL="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
TMP_DIR=$(mktemp -d)
log() { echo "${TIMESTAMP} [RULES] $*" | tee -a "$LOG"; logger -t codered-rules "$*"; }
log "Starting ET rule update..."
if ! curl -sSL --connect-timeout 30 --max-time 120 -o "${TMP_DIR}/emerging.rules.tar.gz" "${ET_URL}"; then
    log "ERROR: Failed to download rules"; rm -rf "${TMP_DIR}"; exit 1
fi
if ! file "${TMP_DIR}/emerging.rules.tar.gz" | grep -q gzip; then
    log "ERROR: Invalid download"; rm -rf "${TMP_DIR}"; exit 1
fi
mkdir -p "${TMP_DIR}/extracted"
tar xzf "${TMP_DIR}/emerging.rules.tar.gz" -C "${TMP_DIR}/extracted"
RULE_COUNT=$(grep -r "^alert\|^drop\|^reject" "${TMP_DIR}/extracted/" 2>/dev/null | wc -l)
log "Downloaded ${RULE_COUNT} rules"
if [ "$RULE_COUNT" -lt 1000 ]; then
    log "WARNING: Rule count too low. Skipping."; rm -rf "${TMP_DIR}"; exit 1
fi
mkdir -p "$RULES_DIR"
[ -d "$RULES_DIR" ] && cp -r "$RULES_DIR" "${RULES_DIR}.bak.$(date +%Y%m%d)" 2>/dev/null || true
find "${TMP_DIR}/extracted" -name "*.rules" -exec cp {} "$RULES_DIR/" \;
ls -dt ${RULES_DIR}.bak.* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
if pgrep -x suricata &>/dev/null; then
    suricatasc -c reload-rules 2>/dev/null && log "Rules reloaded (live)" || \
    systemctl restart suricata 2>/dev/null && log "Suricata restarted" || true
else
    log "Suricata not running — rules will load on next start"
fi
echo "${TIMESTAMP} rules=${RULE_COUNT}" > /var/log/codered/last-rule-update.log
rm -rf "${TMP_DIR}"
log "Rule update complete: ${RULE_COUNT} rules"
RULESCRIPT
chmod 750 "$CODERED_DIR/bin/update-rules.sh"

# Auto-update script
cat > "$CODERED_DIR/bin/codered-update.sh" << 'UPDATESCRIPT'
#!/bin/bash
set -euo pipefail
LOG="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
log() { echo "${TIMESTAMP} [UPDATE] $*" | tee -a "$LOG"; logger -t codered-update "$*"; }
log "Starting CodeRed auto-update..."
[ -d "$REPO_DIR/.git" ] || { log "Repo not configured."; exit 0; }
cd "$REPO_DIR"
BEFORE=$(git rev-parse HEAD)
git pull --ff-only origin "$(git branch --show-current)" >> "$LOG" 2>&1 || { log "ERROR: git pull failed"; exit 1; }
AFTER=$(git rev-parse HEAD)
[ "$BEFORE" = "$AFTER" ] && { log "No updates."; echo "$TIMESTAMP" > /var/log/codered/last-update.log; exit 0; }
log "Updates: ${BEFORE:0:8} -> ${AFTER:0:8}"
[ -f "$REPO_DIR/shell/cli.py" ] && {
    chattr -i /opt/codered/shell/cli.py 2>/dev/null || true
    cp "$REPO_DIR/shell/cli.py" /opt/codered/shell/cli.py
    chattr +i /opt/codered/shell/cli.py 2>/dev/null || true
}
[ -f "$REPO_DIR/VERSION" ] && cp "$REPO_DIR/VERSION" /opt/codered/VERSION
[ -f "$REPO_DIR/conf/codered.defaults" ] && cp "$REPO_DIR/conf/codered.defaults" /etc/codered/codered.defaults
echo "$TIMESTAMP" > /var/log/codered/last-update.log
log "Update complete."
UPDATESCRIPT
chmod 750 "$CODERED_DIR/bin/codered-update.sh"

# Clone repo for auto-updates
git clone --depth 1 "$CODERED_REPO" "$CODERED_DIR/repo" 2>/dev/null || true

# Systemd timers
cat > /etc/systemd/system/codered-rule-update.service << 'EOF'
[Unit]
Description=CodeRed NDR - Suricata Rule Update
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/codered/bin/update-rules.sh
TimeoutStartSec=300
EOF

cat > /etc/systemd/system/codered-rule-update.timer << 'EOF'
[Unit]
Description=CodeRed NDR - Daily Suricata Rule Update
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/codered-update.service << 'EOF'
[Unit]
Description=CodeRed NDR - Config Auto-Update
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/codered/bin/codered-update.sh
TimeoutStartSec=600
EOF

cat > /etc/systemd/system/codered-update.timer << 'EOF'
[Unit]
Description=CodeRed NDR - Config Auto-Update Timer
[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

# Permissions
chown -R root:root "$CODERED_DIR"
chown -R root:adm /var/log/codered
chmod 775 /var/log/codered
chmod 755 /etc/codered

log "CodeRed NDR CLI installed."

# ─── Step 5: Create coderedai User ───────────────

step 5 "Creating coderedai user and applying security..."

# Create user
if ! id coderedai &>/dev/null; then
    useradd -m -s /bin/bash -G adm coderedai
fi
echo "coderedai:coderedai" | chpasswd

# Log file permissions
touch /var/log/codered/cli.log /var/log/codered/audit.log
chown coderedai:adm /var/log/codered/cli.log /var/log/codered/audit.log
chmod 664 /var/log/codered/cli.log /var/log/codered/audit.log

# Restricted shell profile
cat > /etc/profile.d/codered-cli.sh << 'PROFILE'
#!/bin/bash
if [ "$(whoami)" = "coderedai" ]; then
    export PATH=""
    unset ENV BASH_ENV CDPATH GLOBIGNORE
    readonly HISTFILE=/dev/null
    set -r
    logger -t codered-audit "coderedai login from ${SSH_CLIENT%% *:-console}"
    exec /usr/bin/python3 /opt/codered/shell/cli.py
    exit 0
fi
PROFILE
chmod 644 /etc/profile.d/codered-cli.sh

# Lock home files
cat > /home/coderedai/.bashrc << 'EOF'
# CodeRed NDR - Managed
EOF
chown root:coderedai /home/coderedai/.bashrc
chmod 444 /home/coderedai/.bashrc

cat > /home/coderedai/.bash_profile << 'EOF'
# CodeRed NDR - Managed
source /etc/profile
EOF
chown root:coderedai /home/coderedai/.bash_profile
chmod 444 /home/coderedai/.bash_profile

# Sudoers
cat > /etc/sudoers.d/codered << 'SUDOERS'
coderedai ALL=(root) NOPASSWD: /usr/bin/hostnamectl *
coderedai ALL=(root) NOPASSWD: /usr/bin/nmcli *
coderedai ALL=(root) NOPASSWD: /usr/sbin/ip *
coderedai ALL=(root) NOPASSWD: /usr/sbin/ethtool *
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl is-active *
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl restart suricata
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl restart filebeat
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl restart zeek
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start suricata
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start filebeat
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start zeek
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop suricata
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop filebeat
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop zeek
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl status *
coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl enable *
coderedai ALL=(root) NOPASSWD: /usr/bin/docker ps *
coderedai ALL=(root) NOPASSWD: /usr/sbin/shutdown *
coderedai ALL=(root) NOPASSWD: /usr/bin/timedatectl *
coderedai ALL=(root) NOPASSWD: /usr/bin/journalctl *
coderedai ALL=(root) NOPASSWD: /usr/bin/pgrep *
coderedai ALL=(root) NOPASSWD: /usr/bin/cp /tmp/*.conf /etc/codered/sensor.conf
coderedai ALL=(root) NOPASSWD: /usr/bin/chmod 640 /etc/codered/sensor.conf
coderedai ALL=(root) NOPASSWD: /usr/bin/mkdir -p /etc/codered
coderedai ALL=(root) NOPASSWD: /usr/bin/bash -c echo "coderedai\:*" | chpasswd
coderedai ALL=(root) NOPASSWD: /usr/bin/tcpdump *
coderedai ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl *
SUDOERS
chmod 440 /etc/sudoers.d/codered
visudo -cf /etc/sudoers.d/codered || { rm -f /etc/sudoers.d/codered; warn "Sudoers validation failed"; }

log "User coderedai created with restricted access."

# ─── Step 6: Hardening ───────────────────────────

step 6 "Applying security hardening..."

# SSH hardening
cat > /etc/ssh/sshd_config.d/99-codered-hardening.conf << 'SSHCONF'
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
SyslogFacility AUTH
KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

Match User coderedai
    PasswordAuthentication yes
    PubkeyAuthentication no
    ForceCommand /usr/bin/python3 /opt/codered/shell/cli.py

Banner /etc/ssh/codered-banner
SSHCONF
chmod 600 /etc/ssh/sshd_config.d/99-codered-hardening.conf

# Banner
cat > /etc/ssh/codered-banner << 'BANNER'

╔══════════════════════════════════════════════════════════╗
║              CodeRed NDR Appliance                       ║
║                                                          ║
║  Authorized access only. All sessions are logged.        ║
╚══════════════════════════════════════════════════════════╝

BANNER
chmod 644 /etc/ssh/codered-banner

# Test and restart SSH
SSH_SVC="ssh"
systemctl list-units --type=service | grep -q "sshd.service" && SSH_SVC="sshd"

if sshd -t 2>/dev/null; then
    systemctl restart "$SSH_SVC"
    log "SSH hardened."
else
    warn "SSH config test failed. Reverting..."
    rm -f /etc/ssh/sshd_config.d/99-codered-hardening.conf
    systemctl restart "$SSH_SVC"
fi

# Firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow out 9200/tcp comment "CodeRed AI"
ufw allow out 53 comment "DNS"
ufw allow out 123/udp comment "NTP"
ufw allow out 443/tcp comment "HTTPS"
ufw --force enable
log "Firewall configured."

# Fail2ban
cat > /etc/fail2ban/jail.d/codered.conf << 'F2B'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
F2B
systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban 2>/dev/null
log "Fail2ban configured."

# AppArmor
if command -v apparmor_parser &>/dev/null; then
    cat > /etc/apparmor.d/opt.codered.shell.cli << 'APPARMOR'
#include <tunables/global>
/opt/codered/shell/cli.py {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>
  /etc/codered/ r,
  /etc/codered/** r,
  /proc/** r,
  /sys/class/net/** r,
  /usr/bin/ip rix,
  /usr/bin/df rix,
  /usr/bin/uptime rix,
  /usr/bin/hostname rix,
  /usr/bin/tail rix,
  /usr/bin/head rix,
  /usr/bin/systemctl rix,
  /usr/bin/docker rix,
  /usr/sbin/shutdown rix,
  /usr/bin/sudo rix,
  /usr/bin/timedatectl rix,
  /usr/bin/journalctl rix,
  /usr/bin/pgrep rix,
  /usr/bin/host rix,
  /usr/bin/ping rix,
  /var/log/codered/ rw,
  /var/log/codered/** rw,
  /nsm/zeek/logs/** r,
  /nsm/suricata/** r,
  /var/log/syslog r,
  /var/log/auth.log r,
  /tmp/*.conf rw,
  /usr/lib/python3/** r,
  /usr/lib/python3/dist-packages/** r,
  /opt/codered/** r,
  deny /bin/bash x,
  deny /bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/sh x,
  deny /usr/bin/su x,
  deny /usr/bin/apt* x,
  deny /usr/bin/dpkg x,
  deny /usr/bin/pip* x,
  deny /usr/bin/wget x,
  deny /usr/bin/curl x,
  deny /usr/bin/vi x,
  deny /usr/bin/vim x,
  deny /usr/bin/nano x,
}
APPARMOR
    apparmor_parser -r /etc/apparmor.d/opt.codered.shell.cli 2>/dev/null && \
        log "AppArmor profile loaded." || warn "AppArmor profile failed."
fi

# Kernel hardening
cat > /etc/sysctl.d/99-codered-hardening.conf << 'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
SYSCTL
sysctl --system >/dev/null 2>&1

# Core dumps disabled
cat > /etc/security/limits.d/codered-nocore.conf << 'EOF'
* hard core 0
* soft core 0
EOF

# Immutable files
chattr +i "$CODERED_DIR/shell/cli.py" 2>/dev/null || true
chattr +i /etc/profile.d/codered-cli.sh 2>/dev/null || true
chattr +i /etc/ssh/sshd_config.d/99-codered-hardening.conf 2>/dev/null || true

log "Security hardening applied."

# ─── Cleanup ─────────────────────────────────────

rm -rf "$CODERED_SRC"

# ─── Done ────────────────────────────────────────

CURRENT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         CodeRed NDR v${CODERED_VERSION} installed successfully!        ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │                                                          │"
echo "  │  Login:    ssh coderedai@${CURRENT_IP}"
echo "  │  Password: coderedai                                     │"
echo "  │                                                          │"
echo "  │  Next steps:                                             │"
echo "  │    1. SSH in as coderedai                                │"
echo "  │    2. Select monitor interfaces  (option 7)              │"
echo "  │    3. Set CodeRed AI destination (option 8)              │"
echo "  │    4. Start NDR services         (option 9)              │"
echo "  │                                                          │"
echo "  │  Admin access: your existing SSH user still works        │"
echo "  │                                                          │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""
echo "  Installed: Zeek + Suricata + Filebeat + CodeRed NDR CLI"
echo "  Services:  All stopped (start via coderedai menu option 9)"
echo ""

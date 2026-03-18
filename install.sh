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

# ─── Step 5: Install coderedndr Command ──────────

step 5 "Installing coderedndr command..."

# Create the coderedndr command
cat > /usr/local/bin/coderedndr << 'CMD'
#!/bin/bash
# CodeRed NDR Management CLI
# Usage: sudo coderedndr
exec /usr/bin/python3 /opt/codered/shell/cli.py "$@"
CMD
chmod 755 /usr/local/bin/coderedndr

# Log file permissions
touch /var/log/codered/cli.log /var/log/codered/audit.log
chmod 664 /var/log/codered/cli.log /var/log/codered/audit.log

log "Command 'coderedndr' installed. Usage: sudo coderedndr"

# ─── Step 6: Optional Kernel Hardening ───────────

step 6 "Kernel hardening (optional)..."

echo ""
echo "  CodeRed NDR can apply kernel-level security hardening:"
echo ""
echo "    - Block source-routed packets (prevent path manipulation)"
echo "    - Enable SYN flood protection (TCP SYN cookies)"
echo "    - Ignore ICMP redirects (prevent MITM routing attacks)"
echo "    - Log suspicious packets (martian source addresses)"
echo "    - Block broadcast ICMP (prevent Smurf DDoS)"
echo "    - Enable full ASLR (memory exploit mitigation)"
echo "    - Restrict kernel log access (information leak prevention)"
echo "    - Hide kernel memory addresses (exploit mitigation)"
echo ""
echo "  These settings are written to /etc/sysctl.d/99-codered-hardening.conf"
echo "  and will NOT modify your existing sysctl settings."
echo ""
read -p "  Apply kernel hardening? (y/N): " APPLY_HARDENING

if [[ "$APPLY_HARDENING" =~ ^[Yy]$ ]]; then
    cat > /etc/sysctl.d/99-codered-hardening.conf << 'SYSCTL'
# CodeRed NDR - Kernel Hardening
# Applied during install. Remove this file to revert:
#   rm /etc/sysctl.d/99-codered-hardening.conf && sysctl --system

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
SYSCTL
    sysctl --system >/dev/null 2>&1
    log "Kernel hardening applied."
else
    log "Kernel hardening skipped (can be applied later via: sudo coderedndr → Diagnostics)."
fi

# ─── Cleanup ─────────────────────────────────────

rm -rf "$CODERED_SRC"

# ─── Done ────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║         CodeRed NDR v${CODERED_VERSION} installed successfully!        ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │                                                          │"
echo "  │  Run:  sudo coderedndr                                   │"
echo "  │                                                          │"
echo "  │  Next steps:                                             │"
echo "  │    1. sudo coderedndr                                    │"
echo "  │    2. Select monitor interfaces  (option 7)              │"
echo "  │    3. Set CodeRed AI destination (option 8)              │"
echo "  │    4. Start NDR services         (option 9)              │"
echo "  │                                                          │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""
echo "  Installed: Zeek + Suricata + Filebeat + coderedndr CLI"
echo "  Services:  All stopped (start via coderedndr menu option 9)"
echo ""

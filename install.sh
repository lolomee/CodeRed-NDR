#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║         CodeRed NDR - Unified Sensor Installer           ║
# ║                                                          ║
# ║  Usage:                                                  ║
# ║  curl -sSL https://raw.githubusercontent.com/            ║
# ║    lolomee/CodeRed-NDR/main/install.sh | sudo bash       ║
# ║                                                          ║
# ║  Or run locally:                                         ║
# ║    sudo bash install.sh                                  ║
# ╚══════════════════════════════════════════════════════════╝
#
# This is the ONLY install script needed for CodeRed NDR.
# It installs: Zeek, Suricata, Filebeat, and the CodeRed management CLI.
# Services are installed but NOT started (use coderedndr menu to start).
# Safe to run multiple times (idempotent).

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Constants ─────────────────────────────────────────────

CODERED_REPO="https://github.com/lolomee/CodeRed-NDR.git"
CODERED_DIR="/opt/codered"
CODERED_SRC="/tmp/codered-ndr-install"
STEP_TOTAL=8

# ─── Helpers ───────────────────────────────────────────────

log()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*"; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}[$1/${STEP_TOTAL}]${NC} ${BOLD}$2${NC}"; }

# Detect whether stdin is a pipe (curl | bash mode).
# When piped, interactive prompts cannot work; use defaults.
is_piped() { [ ! -t 0 ]; }

# Safe prompt: works in pipe mode by reading from /dev/tty.
# Falls back to default value if /dev/tty is unavailable.
prompt() {
    local msg="$1" default="$2" varname="$3"
    if is_piped; then
        if [ -r /dev/tty ]; then
            read -rp "  $msg" "$varname" < /dev/tty || eval "$varname='$default'"
        else
            eval "$varname='$default'"
        fi
    else
        read -rp "  $msg" "$varname" || eval "$varname='$default'"
    fi
}

# ─── Determine version ────────────────────────────────────

# If running from a git checkout, read VERSION from the repo.
# Otherwise default to 2.0.0.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" 2>/dev/null || echo ".")" && pwd)"
if [ -f "${SCRIPT_DIR}/VERSION" ]; then
    CODERED_VERSION=$(cat "${SCRIPT_DIR}/VERSION" | tr -d '[:space:]')
else
    CODERED_VERSION="2.0.0"
fi

# ─── Banner ────────────────────────────────────────────────

echo ""
echo -e "${BOLD}"
echo "  +----------------------------------------------------------+"
echo "  |           CodeRed NDR - Sensor Installer                 |"
echo "  |           Version ${CODERED_VERSION}                                 |"
echo "  +----------------------------------------------------------+"
echo -e "${NC}"

# ─── Pre-flight Checks ────────────────────────────────────

[ "$(id -u)" -eq 0 ] || err "This script must be run as root. Use: curl ... | sudo bash"

if [ ! -f /etc/os-release ]; then
    err "Cannot detect OS. Only Ubuntu 22.04/24.04 is supported."
fi

# shellcheck source=/dev/null
. /etc/os-release

if [ "$ID" != "ubuntu" ]; then
    err "Unsupported OS: $ID. Only Ubuntu is supported."
fi

UBUNTU_VER="$VERSION_ID"
if [[ "$UBUNTU_VER" != "22.04" && "$UBUNTU_VER" != "24.04" ]]; then
    warn "Ubuntu $UBUNTU_VER detected. Tested on 22.04 and 24.04. Continuing anyway..."
fi

ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    err "Unsupported architecture: $ARCH. Only amd64 is supported."
fi

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

# ─── Idempotent: check existing install ───────────────────

if [ -f "${CODERED_DIR}/VERSION" ]; then
    EXISTING_VER=$(cat "${CODERED_DIR}/VERSION" | tr -d '[:space:]')
    warn "CodeRed NDR v${EXISTING_VER} is already installed."
    echo ""
    REPLY=""
    prompt "Reinstall/upgrade? (y/N): " "N" REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo "  Cancelled."
        exit 0
    fi
fi

# ═══════════════════════════════════════════════════════════
# Step 1: Install system dependencies
# ═══════════════════════════════════════════════════════════

step 1 "Installing system dependencies..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq

apt-get install -y -qq \
    curl \
    gnupg \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    lsb-release \
    python3 \
    python3-configparser \
    python3-pam \
    netcat-openbsd \
    dialog \
    ethtool \
    net-tools \
    jq \
    git \
    tcpdump \
    open-vm-tools \
    logrotate \
    2>/dev/null || true

log "System dependencies installed."

# ═══════════════════════════════════════════════════════════
# Step 2: Install Zeek (from APT repository)
# ═══════════════════════════════════════════════════════════

step 2 "Installing Zeek..."

if command -v zeek &>/dev/null || [ -x /opt/zeek/bin/zeek ]; then
    log "Zeek already installed: $(/opt/zeek/bin/zeek --version 2>/dev/null || zeek --version 2>/dev/null || echo 'found')"
else
    ZEEK_INSTALLED=false

    # Method 1: OpenSUSE OBS repository for current Ubuntu version
    ZEEK_KEY_URL="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}/Release.key"
    if curl -fsSL "$ZEEK_KEY_URL" 2>/dev/null | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg 2>/dev/null; then
        echo "deb [signed-by=/etc/apt/trusted.gpg.d/zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VER}/ /" \
            > /etc/apt/sources.list.d/zeek.list
        apt-get update -qq 2>/dev/null
    else
        warn "Failed to fetch Zeek GPG key for Ubuntu ${UBUNTU_VER}."
    fi

    if apt-get install -y -qq zeek 2>/dev/null; then
        ZEEK_INSTALLED=true
    fi

    # Method 2: Try 22.04 repo on 24.04 (fallback)
    if [ "$ZEEK_INSTALLED" = false ] && [ "$UBUNTU_VER" = "24.04" ]; then
        rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/zeek.gpg
        ZEEK_KEY_URL="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key"
        if curl -fsSL "$ZEEK_KEY_URL" 2>/dev/null | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg 2>/dev/null; then
            echo "deb [signed-by=/etc/apt/trusted.gpg.d/zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
                > /etc/apt/sources.list.d/zeek.list
            apt-get update -qq 2>/dev/null
        fi
        if apt-get install -y -qq zeek 2>/dev/null; then
            ZEEK_INSTALLED=true
        fi
    fi

    if [ "$ZEEK_INSTALLED" = false ]; then
        warn "Zeek package installation failed. Install manually: https://zeek.org/get-zeek/"
        warn "Zeek will be expected at /opt/zeek/bin/zeek."
    fi
fi

# Ensure Zeek is on PATH
if [ -d /opt/zeek/bin ]; then
    echo 'export PATH=/opt/zeek/bin:$PATH' > /etc/profile.d/zeek-path.sh
    chmod 644 /etc/profile.d/zeek-path.sh
    export PATH=/opt/zeek/bin:$PATH
fi

# Do not autostart Zeek — managed by CodeRed
systemctl disable zeek 2>/dev/null || true
systemctl stop zeek 2>/dev/null || true

if [ -x /opt/zeek/bin/zeek ]; then
    log "Zeek installed: $(/opt/zeek/bin/zeek --version 2>/dev/null)"
fi

# ═══════════════════════════════════════════════════════════
# Step 3: Install Suricata + Filebeat (from APT repositories)
# ═══════════════════════════════════════════════════════════

step 3 "Installing Suricata and Filebeat..."

# --- Suricata ---
if ! command -v suricata &>/dev/null; then
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    apt-get update -qq
    apt-get install -y -o Dpkg::Options::="--force-overwrite" suricata suricata-update 2>/dev/null || \
    apt-get install -y suricata 2>/dev/null || true
fi

# Disable autostart — managed by CodeRed
systemctl disable suricata 2>/dev/null || true
systemctl stop suricata 2>/dev/null || true

if command -v suricata &>/dev/null; then
    # Enable community-id for correlation with Zeek
    sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml 2>/dev/null || true
    log "Suricata installed: $(suricata -V 2>&1 | head -1)"
else
    warn "Suricata installation failed. Install manually."
fi

# --- Filebeat ---
if ! command -v filebeat &>/dev/null; then
    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch 2>/dev/null \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg 2>/dev/null || true
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
        > /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update -qq
    apt-get install -y -qq filebeat 2>/dev/null || true
fi

# Disable autostart — managed by CodeRed
systemctl disable filebeat 2>/dev/null || true
systemctl stop filebeat 2>/dev/null || true

if command -v filebeat &>/dev/null; then
    log "Filebeat installed: $(filebeat version 2>/dev/null | head -1)"
else
    warn "Filebeat installation failed. Install manually."
fi

# ═══════════════════════════════════════════════════════════
# Step 4: Deploy CodeRed NDR files
# ═══════════════════════════════════════════════════════════

step 4 "Deploying CodeRed NDR files..."

# --- Clone or update source repo ---
rm -rf "$CODERED_SRC"
if [ -d "${SCRIPT_DIR}/.git" ] && [ -f "${SCRIPT_DIR}/shell/cli.py" ]; then
    # Running from a local git checkout — use it directly
    CODERED_SRC="${SCRIPT_DIR}"
    log "Using local repo at ${CODERED_SRC}."
elif git clone --depth 1 "$CODERED_REPO" "$CODERED_SRC" 2>/dev/null; then
    log "Downloaded CodeRed NDR from GitHub."
else
    err "Failed to clone CodeRed NDR repo. Check internet connection."
fi

# Re-read version from source
if [ -f "${CODERED_SRC}/VERSION" ]; then
    CODERED_VERSION=$(cat "${CODERED_SRC}/VERSION" | tr -d '[:space:]')
fi

# --- Create directory structure ---

mkdir -p "${CODERED_DIR}"/{shell,bin,firstboot,repo}
mkdir -p /etc/codered
mkdir -p /var/log/codered
mkdir -p /nsm/zeek/logs/current
mkdir -p /nsm/suricata/log
mkdir -p /nsm/suricata/rules
mkdir -p /nsm/pcap

# --- Copy files from repo ---

# CLI
cp "${CODERED_SRC}/shell/cli.py" "${CODERED_DIR}/shell/cli.py"
# Restricted shell profile (if present)
[ -f "${CODERED_SRC}/shell/rbash_profile" ] && \
    cp "${CODERED_SRC}/shell/rbash_profile" "${CODERED_DIR}/shell/rbash_profile"

# Firstboot
cp "${CODERED_SRC}/firstboot/firstboot.sh" "${CODERED_DIR}/firstboot/firstboot.sh"

# Config defaults
cp "${CODERED_SRC}/conf/codered.defaults" /etc/codered/codered.defaults

# Bin scripts — copy anything that exists in the repo
if [ -d "${CODERED_SRC}/bin" ]; then
    cp "${CODERED_SRC}"/bin/* "${CODERED_DIR}/bin/" 2>/dev/null || true
fi

# Zeek detection scripts — copy to /opt/codered/zeek/
mkdir -p /opt/codered/zeek
if [ -d "${CODERED_SRC}/zeek/codered-detections" ]; then
    cp -r "${CODERED_SRC}/zeek/codered-detections" /opt/codered/zeek/
    log "Detection scripts deployed: $(ls /opt/codered/zeek/codered-detections/*.zeek 2>/dev/null | wc -l) scripts"
fi

# Zeek site local.zeek — deploy to /opt/zeek/share/zeek/site/
# This is the main Zeek config that loads all CodeRed detection scripts.
# It will be modified by the CLI when cloud_mode is toggled.
ZEEK_SITE_DIR="/opt/zeek/share/zeek/site"
if [ -d "$ZEEK_SITE_DIR" ]; then
    if [ -f "${CODERED_SRC}/zeek/site/local.zeek" ]; then
        cp "${CODERED_SRC}/zeek/site/local.zeek" "${ZEEK_SITE_DIR}/local.zeek"
        chmod 644 "${ZEEK_SITE_DIR}/local.zeek"
        log "Zeek site config deployed to ${ZEEK_SITE_DIR}/local.zeek"
    fi
else
    warn "Zeek site directory not found at ${ZEEK_SITE_DIR}. Install Zeek first."
fi

# Auto-update script
if [ -f "${CODERED_SRC}/bin/codered-update.sh" ]; then
    cp "${CODERED_SRC}/bin/codered-update.sh" "${CODERED_DIR}/bin/codered-update.sh"
fi

# VERSION file
echo "${CODERED_VERSION}" > "${CODERED_DIR}/VERSION"

# --- Create update-rules.sh (uses suricata-update, not manual download) ---

cat > "${CODERED_DIR}/bin/update-rules.sh" << 'RULESCRIPT'
#!/bin/bash
# CodeRed NDR - Suricata rule update via suricata-update
set -euo pipefail

LOG="/var/log/codered/rule-update.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() { echo "${TIMESTAMP} [RULES] $*" | tee -a "$LOG"; logger -t codered-rules "$*"; }

log "Starting Suricata rule update..."

if ! command -v suricata-update &>/dev/null; then
    log "ERROR: suricata-update not found. Install suricata first."
    exit 1
fi

# Enable common free sources
suricata-update enable-source et/open 2>/dev/null || true
suricata-update enable-source oisf/trafficid 2>/dev/null || true

# Run the update
if suricata-update --no-test 2>&1 | tee -a "$LOG"; then
    RULE_COUNT=$(suricata-update list-enabled-sources 2>/dev/null | wc -l)
    log "Rule update successful (${RULE_COUNT} sources enabled)."
else
    log "ERROR: suricata-update failed."
    exit 1
fi

# Reload Suricata if running
if pgrep -x suricata &>/dev/null; then
    suricatasc -c reload-rules 2>/dev/null && log "Rules reloaded (live)." || \
    { systemctl restart suricata 2>/dev/null && log "Suricata restarted."; } || true
else
    log "Suricata not running - rules will load on next start."
fi

echo "${TIMESTAMP}" > /var/log/codered/last-rule-update.log
log "Rule update complete."
RULESCRIPT

# --- Create codered-update.sh if not already copied from repo ---

if [ ! -f "${CODERED_DIR}/bin/codered-update.sh" ]; then
    cat > "${CODERED_DIR}/bin/codered-update.sh" << 'UPDATESCRIPT'
#!/bin/bash
# CodeRed NDR - Auto-Update Script
set -euo pipefail

LOG="/var/log/codered/update.log"
REPO_DIR="/opt/codered/repo"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() { echo "${TIMESTAMP} [UPDATE] $*" | tee -a "$LOG"; logger -t codered-update "$*"; }

log "Starting CodeRed auto-update..."

[ -d "$REPO_DIR/.git" ] || { log "Update repo not configured. Skipping."; exit 0; }

cd "$REPO_DIR"
BEFORE=$(git rev-parse HEAD)

if ! git pull --ff-only origin "$(git branch --show-current)" >> "$LOG" 2>&1; then
    log "ERROR: git pull failed."
    exit 1
fi

AFTER=$(git rev-parse HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
    log "No updates available."
    echo "$TIMESTAMP" > /var/log/codered/last-update.log
    exit 0
fi

log "Updates: ${BEFORE:0:8} -> ${AFTER:0:8}"

# Sync updated files
[ -f "$REPO_DIR/shell/cli.py" ] && {
    chattr -i /opt/codered/shell/cli.py 2>/dev/null || true
    cp "$REPO_DIR/shell/cli.py" /opt/codered/shell/cli.py
    chmod 755 /opt/codered/shell/cli.py
    chattr +i /opt/codered/shell/cli.py 2>/dev/null || true
}
[ -f "$REPO_DIR/VERSION" ] && cp "$REPO_DIR/VERSION" /opt/codered/VERSION
[ -f "$REPO_DIR/conf/codered.defaults" ] && cp "$REPO_DIR/conf/codered.defaults" /etc/codered/codered.defaults
[ -d "$REPO_DIR/bin" ] && cp "$REPO_DIR"/bin/* /opt/codered/bin/ 2>/dev/null || true
[ -f "$REPO_DIR/firstboot/firstboot.sh" ] && cp "$REPO_DIR/firstboot/firstboot.sh" /opt/codered/firstboot/firstboot.sh

echo "$TIMESTAMP" > /var/log/codered/last-update.log
log "Update complete."
UPDATESCRIPT
fi

# --- Clone repo for auto-updates ---

if [ -d "${CODERED_DIR}/repo/.git" ]; then
    log "Update repo already present, pulling latest..."
    git -C "${CODERED_DIR}/repo" pull --ff-only 2>/dev/null || true
else
    rm -rf "${CODERED_DIR}/repo"
    git clone --depth 1 "$CODERED_REPO" "${CODERED_DIR}/repo" 2>/dev/null || \
        warn "Could not clone update repo. Auto-updates will not work until configured."
fi

# --- Create coderedndr command ---

cat > /usr/local/bin/coderedndr << 'CMD'
#!/bin/bash
# CodeRed NDR Management CLI
# Usage: sudo coderedndr
exec /usr/bin/python3 /opt/codered/shell/cli.py "$@"
CMD
chmod 755 /usr/local/bin/coderedndr

log "CodeRed NDR files deployed."

# ═══════════════════════════════════════════════════════════
# Step 5: Download initial Suricata rules + GeoIP
# ═══════════════════════════════════════════════════════════

step 5 "Downloading Suricata rules and GeoIP database..."

# --- Suricata rules via suricata-update ---
if command -v suricata-update &>/dev/null; then
    suricata-update enable-source et/open 2>/dev/null || true
    suricata-update enable-source oisf/trafficid 2>/dev/null || true
    if suricata-update --no-test 2>/dev/null; then
        log "Suricata rules downloaded via suricata-update."
    else
        warn "suricata-update failed. Rules will download on first timer run."
    fi
else
    warn "suricata-update not found. Rules will download when Suricata is installed."
fi

# --- GeoIP database ---
mkdir -p /usr/share/GeoIP
if curl -sSL --max-time 60 -o /usr/share/GeoIP/GeoLite2-City.mmdb \
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" 2>/dev/null; then
    log "GeoIP database installed."
else
    warn "GeoIP download failed (non-critical)."
fi

# ═══════════════════════════════════════════════════════════
# Step 6: SSH hardening
# ═══════════════════════════════════════════════════════════

step 6 "Hardening SSH and installing fail2ban..."

# --- SSH daemon hardening ---
SSHD_HARDENING="/etc/ssh/sshd_config.d/90-codered-hardening.conf"
cat > "$SSHD_HARDENING" << 'SSHD'
# CodeRed NDR — SSH hardening
# Applied by install.sh — do not edit manually

# Disable root login entirely
PermitRootLogin no

# Key-based auth only for production; password auth for initial customer setup
PasswordAuthentication yes
PubkeyAuthentication yes

# Harden authentication
MaxAuthTries 4
MaxStartups 10:30:60
LoginGraceTime 30

# Disable dangerous features
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitUserEnvironment no

# Idle timeout: disconnect after 15 min of inactivity
ClientAliveInterval 300
ClientAliveCountMax 3

# Restrict to secure algorithms only
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Log verbosity for audit
LogLevel VERBOSE

# Login banner
Banner /etc/issue.net
SSHD
chmod 644 "$SSHD_HARDENING"

# Apply SSH banner
cat > /etc/issue.net << 'BANNER'

  ══════════════════════════════════════════════════════
       CodeRed NDR Sensor — Authorized Access Only
       Unauthorized access is prohibited and logged.
  ══════════════════════════════════════════════════════

BANNER

# Reload SSH to apply hardening
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
log "SSH hardened: MaxAuthTries=4, root login disabled, idle timeout 15min"

# --- Install and configure fail2ban ---
if apt-get install -y -qq fail2ban 2>/dev/null; then
    cat > /etc/fail2ban/jail.d/codered-sshd.conf << 'F2B'
[sshd]
enabled   = true
port      = ssh
logpath   = %(sshd_log)s
backend   = %(sshd_backend)s
maxretry  = 4
findtime  = 300
bantime   = 1800
F2B
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
    log "fail2ban configured: 4 attempts / 5 min → 30 min ban"
else
    warn "fail2ban install failed — SSH brute force protection not active"
fi

# ═══════════════════════════════════════════════════════════
# Step 7: Install ML behavioral engine
# ═══════════════════════════════════════════════════════════

step 7 "Installing ML behavioral engine..."

# Install Python ML dependencies
pip3 install --quiet --break-system-packages \
    scikit-learn numpy 2>/dev/null || \
pip3 install --quiet \
    scikit-learn numpy 2>/dev/null || true

# Deploy ML engine from source repo
mkdir -p /opt/codered/ml
if [ -f "${CODERED_SRC}/ml/codered-ml.py" ]; then
    cp "${CODERED_SRC}/ml/codered-ml.py" /opt/codered/ml/codered-ml.py
    chmod 750 /opt/codered/ml/codered-ml.py
    log "ML engine deployed from source"
else
    warn "ML engine source not found at ${CODERED_SRC}/ml/codered-ml.py — skipping"
fi

# Create ML output directory
mkdir -p /nsm/codered
chmod 750 /nsm/codered

# Add ML alert input to Filebeat config
if [ -f /etc/filebeat/filebeat.yml ] && \
   ! grep -q "codered-ml-alerts" /etc/filebeat/filebeat.yml; then
    cat >> /etc/filebeat/filebeat.yml << 'FBML'

# CodeRed NDR - ML behavioral anomaly alerts
- type: log
  id: codered-ml-alerts
  enabled: true
  paths:
    - /nsm/codered/ml-alerts.json
  json.keys_under_root: true
  json.add_error_key: true
  json.overwrite_keys: true
  fields:
    source: codered-ml
    log_type: behavioral_anomaly
  fields_under_root: false
  ignore_older: 24h
FBML
fi

log "ML behavioral engine installed"
log "Note: ML models need 50h of traffic data before anomaly detection activates"

# ═══════════════════════════════════════════════════════════
# Step 8: Create systemd units and set permissions
# ═══════════════════════════════════════════════════════════

step 8 "Creating systemd units and setting permissions..."

# --- codered-zeek.service ---
cat > /etc/systemd/system/codered-zeek.service << 'EOF'
[Unit]
Description=CodeRed NDR - Zeek Network Monitor
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/lolomee/CodeRed-NDR

[Service]
Type=forking
Environment="PATH=/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
Restart=on-failure
RestartSec=30
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

# --- codered-suricata.service ---
cat > /etc/systemd/system/codered-suricata.service << 'EOF'
[Unit]
Description=CodeRed NDR - Suricata IDS/IPS
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/lolomee/CodeRed-NDR

[Service]
Type=simple
ExecStartPre=/usr/bin/suricata -T -c /etc/suricata/suricata.yaml
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# --- codered-firstboot.service ---
cat > /etc/systemd/system/codered-firstboot.service << 'EOF'
[Unit]
Description=CodeRed NDR - First Boot Setup Wizard
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/etc/codered/.setup-complete

[Service]
Type=oneshot
ExecStart=/opt/codered/firstboot/firstboot.sh
RemainAfterExit=yes
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1

[Install]
WantedBy=multi-user.target
EOF

# --- codered-rule-update.service + timer ---
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

# --- codered-update.service + timer ---
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

# --- codered-ml.service (ML behavioral engine) ---
cp "${CODERED_SRC}/ml/codered-ml.service" /etc/systemd/system/codered-ml.service \
    2>/dev/null || \
cat > /etc/systemd/system/codered-ml.service << 'EOF'
[Unit]
Description=CodeRed NDR - Behavioral ML Engine
After=network-online.target codered-zeek.service
Wants=codered-zeek.service

[Service]
Type=simple
User=root
ExecStartPre=/usr/bin/mkdir -p /nsm/codered /var/lib/codered /var/log/codered
ExecStart=/usr/bin/python3 /opt/codered/ml/codered-ml.py
Restart=on-failure
RestartSec=10
CPUQuota=25%
MemoryMax=512M
Nice=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Enable timers (but not the main services — those are started via coderedndr menu)
systemctl enable codered-rule-update.timer 2>/dev/null || true
systemctl enable codered-update.timer 2>/dev/null || true
systemctl enable codered-firstboot.service 2>/dev/null || true

log "Systemd units created."

# --- Permissions ---

# /opt/codered
chown -R root:root "${CODERED_DIR}"
chmod 755 "${CODERED_DIR}"
chmod 755 "${CODERED_DIR}/shell/cli.py"
chmod 644 "${CODERED_DIR}/shell/rbash_profile" 2>/dev/null || true
chmod 755 "${CODERED_DIR}/firstboot/firstboot.sh"
chmod 750 "${CODERED_DIR}/bin/"*.sh 2>/dev/null || true
chmod 644 "${CODERED_DIR}/VERSION"

# /etc/codered
chown -R root:root /etc/codered
chmod 755 /etc/codered
chmod 644 /etc/codered/codered.defaults

# /var/log/codered
chown -R root:adm /var/log/codered
chmod 775 /var/log/codered
touch /var/log/codered/cli.log /var/log/codered/audit.log
chmod 664 /var/log/codered/cli.log /var/log/codered/audit.log

# /nsm
chown -R root:adm /nsm
chmod 750 /nsm
chmod -R 750 /nsm/zeek /nsm/suricata /nsm/pcap
# NSM logs: zeek/suricata write as their service users
chown -R zeek:adm /nsm/zeek       2>/dev/null || true
chown -R suricata:adm /nsm/suricata 2>/dev/null || true

log "Permissions set."

# ─── Cleanup ──────────────────────────────────────────────

# Only clean up if we cloned to /tmp
if [ "$CODERED_SRC" = "/tmp/codered-ndr-install" ]; then
    rm -rf "$CODERED_SRC"
fi

# ─── Done ─────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  +----------------------------------------------------------+"
echo "  |     CodeRed NDR v${CODERED_VERSION} installed successfully!          |"
echo "  +----------------------------------------------------------+"
echo -e "${NC}"
echo "  Installed components:"
echo "    - Zeek       (network protocol analysis)"
echo "    - Suricata   (intrusion detection)"
echo "    - Filebeat   (log forwarding)"
echo "    - coderedndr (management CLI)"
echo ""
echo "  Directory structure:"
echo "    /opt/codered/      - CodeRed application files"
echo "    /etc/codered/      - Configuration"
echo "    /nsm/              - Network security monitoring data"
echo "    /var/log/codered/  - Logs"
echo ""
echo "  Next steps:"
echo "    1. sudo coderedndr"
echo "    2. Set deployment mode        (option 9 — on-prem or cloud)"
echo "    3. Select monitor interfaces  (option 7)"
echo "    4. Set SIEM destination       (option 8)"
echo "    5. Start NDR services         (option 10)"
echo ""
echo "  Services are stopped. Start them via the coderedndr menu."
echo ""

  #!/bin/bash
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

  log()  { echo -e "${GREEN}[+]${NC} $*"; }
  warn() { echo -e "${YELLOW}[!]${NC} $*"; }
  err()  { echo -e "${RED}[x]${NC} $*"; exit 1; }
  step() { echo -e "\n${CYAN}${BOLD}[$1/6]${NC} ${BOLD}$2${NC}"; }

  echo ""
  echo -e "${BOLD}"
  echo "  CodeRed NDR - Software Installer v${CODERED_VERSION}"
  echo -e "${NC}"

  [ "$(id -u)" -eq 0 ] || err "This script must be run as root. Use: curl ... | sudo bash"

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

  # --- Step 1: Install Dependencies ---

  step 1 "Installing dependencies..."

  export DEBIAN_FRONTEND=noninteractive

  rm -f /etc/apt/sources.list.d/zeek.list \
        /etc/apt/trusted.gpg.d/zeek.gpg \
        /etc/apt/trusted.gpg.d/security_zeek.gpg \
        /etc/apt/keyrings/security_zeek.gpg

  apt-get update -qq
  apt-get install -y -qq \
      curl gnupg software-properties-common apt-transport-https \
      ca-certificates lsb-release python3 dialog ethtool net-tools \
      jq git ufw apparmor apparmor-utils fail2ban tcpdump \
      open-vm-tools logrotate 2>/dev/null || true

  log "Dependencies installed."

  # --- Step 2: Install Zeek ---

  step 2 "Installing Zeek..."

  if command -v zeek &>/dev/null || [ -x /opt/zeek/bin/zeek ]; then
      log "Zeek already installed: $(/opt/zeek/bin/zeek --version 2>/dev/null || zeek --version 2>/dev/null || echo 'found')"
  else
      ZEEK_INSTALLED=false
      ZEEK_GPG="/etc/apt/keyrings/security_zeek.gpg"
      mkdir -p /etc/apt/keyrings

      rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/zeek.gpg \
            /etc/apt/trusted.gpg.d/security_zeek.gpg "$ZEEK_GPG"

      install_zeek_from_obs() {
          local ubuntu_ver="$1"
          local key_url="https://download.opensuse.org/repositories/security:zeek/xUbuntu_${ubuntu_ver}/Release.key"
          local repo_url="http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ubuntu_ver}/"
          local tmp_key

          tmp_key=$(mktemp)
          rm -f "$ZEEK_GPG" /etc/apt/sources.list.d/zeek.list

          if ! curl -fsSL --connect-timeout 15 --max-time 30 -o "$tmp_key" "$key_url"; then
              warn "Failed to download Zeek GPG key for xUbuntu_${ubuntu_ver}."
              rm -f "$tmp_key"
              return 1
          fi

          if ! grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$tmp_key"; then
              warn "Downloaded file is not a valid GPG key for xUbuntu_${ubuntu_ver}."
              rm -f "$tmp_key"
              return 1
          fi

          if ! gpg --yes --dearmor -o "$ZEEK_GPG" "$tmp_key" 2>/dev/null; then
              warn "GPG dearmor failed for xUbuntu_${ubuntu_ver}."
              rm -f "$tmp_key" "$ZEEK_GPG"
              return 1
          fi
          rm -f "$tmp_key"

          if [ ! -s "$ZEEK_GPG" ]; then
              warn "GPG keyring is empty for xUbuntu_${ubuntu_ver}."
              rm -f "$ZEEK_GPG"
              return 1
          fi

          chmod 644 "$ZEEK_GPG"

          echo "deb [signed-by=${ZEEK_GPG}] ${repo_url} /" > /etc/apt/sources.list.d/zeek.list
          apt-get update -qq

          if apt-get install -y -qq zeek 2>/dev/null; then
              return 0
          else
              rm -f /etc/apt/sources.list.d/zeek.list "$ZEEK_GPG"
              return 1
          fi
      }

      if install_zeek_from_obs "$UBUNTU_VER"; then
          ZEEK_INSTALLED=true
      fi

      if [ "$ZEEK_INSTALLED" = false ] && [ "$UBUNTU_VER" = "24.04" ]; then
          if install_zeek_from_obs "22.04"; then
              ZEEK_INSTALLED=true
          fi
      fi

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

  echo 'export PATH=/opt/zeek/bin:$PATH' > /etc/profile.d/zeek-path.sh
  export PATH=/opt/zeek/bin:$PATH

  systemctl disable zeek 2>/dev/null || true
  systemctl stop zeek 2>/dev/null || true

  if [ -x /opt/zeek/bin/zeek ]; then
      log "Zeek installed: $(/opt/zeek/bin/zeek --version 2>/dev/null)"
  fi

  # --- Step 3: Install Suricata + Filebeat ---

  step 3 "Installing Suricata and Filebeat..."

  if ! command -v suricata &>/dev/null; then
      add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
      apt-get update -qq
      apt-get install -y -o Dpkg::Options::="--force-overwrite" suricata suricata-update 2>/dev/null || \
      apt-get install -y suricata 2>/dev/null || true
  fi

  systemctl disable suricata 2>/dev/null || true
  systemctl stop suricata 2>/dev/null || true

  if command -v suricata &>/dev/null; then
      sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml 2>/dev/null || true
      log "Suricata installed: $(suricata -V 2>&1 | head -1)"
  else
      warn "Suricata installation failed. Install manually."
  fi

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

  # --- Step 4: Install CodeRed NDR ---

  step 4 "Installing CodeRed NDR management CLI..."

  rm -rf "$CODERED_SRC"
  if git clone --depth 1 "$CODERED_REPO" "$CODERED_SRC" 2>/dev/null; then
      log "Downloaded CodeRed NDR from GitHub."
  else
      err "Failed to clone CodeRed NDR repo. Check internet connection."
  fi

  mkdir -p "$CODERED_DIR"/{shell,bin}
  mkdir -p /etc/codered
  mkdir -p /var/log/codered
  mkdir -p /nsm/{zeek/logs/current,suricata,pcap}

  cp "$CODERED_SRC/shell/cli.py" "$CODERED_DIR/shell/cli.py"
  chmod 755 "$CODERED_DIR/shell/cli.py"

  cp "$CODERED_SRC/conf/codered.defaults" /etc/codered/codered.defaults
  chmod 644 /etc/codered/codered.defaults

  echo "$CODERED_VERSION" > "$CODERED_DIR/VERSION"

  # Rule update script
  cat > "$CODERED_DIR/bin/update-rules.sh" << 'RULEEOF'
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
      log "Suricata not running -- rules will load on next start"
  fi
  echo "${TIMESTAMP} rules=${RULE_COUNT}" > /var/log/codered/last-rule-update.log
  rm -rf "${TMP_DIR}"
  log "Rule update complete: ${RULE_COUNT} rules"
  RULEEOF
  chmod 750 "$CODERED_DIR/bin/update-rules.sh"

  # Auto-update script
  cat > "$CODERED_DIR/bin/codered-update.sh" << 'UPDATEEOF'
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
  UPDATEEOF
  chmod 750 "$CODERED_DIR/bin/codered-update.sh"

  git clone --depth 1 "$CODERED_REPO" "$CODERED_DIR/repo" 2>/dev/null || true

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

  chown -R root:root "$CODERED_DIR"
  chown -R root:adm /var/log/codered
  chmod 775 /var/log/codered
  chmod 755 /etc/codered

  log "CodeRed NDR CLI installed."

  # --- Step 4b: Download initial Suricata rules ---

  log "Downloading initial Suricata rules..."
  if command -v suricata-update &>/dev/null; then
      suricata-update enable-source et/open 2>/dev/null || true
      suricata-update enable-source oisf/trafficid 2>/dev/null || true
      suricata-update 2>/dev/null && log "Suricata rules downloaded via suricata-update." || {
          RULES_TMP=$(mktemp -d)
          curl -sSL --max-time 120 -o "${RULES_TMP}/emerging.rules.tar.gz" \
              "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz" 2>/dev/null && {
              mkdir -p /etc/suricata/rules
              tar xzf "${RULES_TMP}/emerging.rules.tar.gz" -C "${RULES_TMP}"
              find "${RULES_TMP}" -name "*.rules" -exec cp {} /etc/suricata/rules/ \;
              RULE_COUNT=$(grep -r "^alert\|^drop" /etc/suricata/rules/*.rules 2>/dev/null | wc -l)
              log "Downloaded ${RULE_COUNT} Suricata rules."
          } || warn "Rule download failed. Rules will download on first timer run (3 AM)."
          rm -rf "${RULES_TMP}"
      }
  else
      warn "suricata-update not found. Rules will download on first timer run."
  fi

  log "Downloading GeoIP database..."
  mkdir -p /usr/share/GeoIP
  curl -sSL --max-time 60 -o /usr/share/GeoIP/GeoLite2-City.mmdb \
      "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" 2>/dev/null && \
      log "GeoIP database installed." || warn "GeoIP download failed (non-critical)."

  # --- Step 5: Install coderedndr Command ---

  step 5 "Installing coderedndr command..."

  cat > /usr/local/bin/coderedndr << 'CMD'
  #!/bin/bash
  exec /usr/bin/python3 /opt/codered/shell/cli.py "$@"
  CMD
  chmod 755 /usr/local/bin/coderedndr

  touch /var/log/codered/cli.log /var/log/codered/audit.log
  chmod 664 /var/log/codered/cli.log /var/log/codered/audit.log

  log "Command 'coderedndr' installed. Usage: sudo coderedndr"

  # --- Step 6: Optional Kernel Hardening ---

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
      log "Kernel hardening skipped (can apply later via sudo coderedndr)."
  fi

  # --- Cleanup ---

  rm -rf "$CODERED_SRC"

  # --- Done ---

  echo ""
  echo -e "${GREEN}${BOLD}"
  echo "  CodeRed NDR v${CODERED_VERSION} installed successfully!"
  echo -e "${NC}"
  echo "  Next steps:"
  echo "    1. sudo coderedndr"
  echo "    2. Select monitor interfaces  (option 7)"
  echo "    3. Set CodeRed AI destination (option 8)"
  echo "    4. Start NDR services         (option 9)"
  echo ""
  echo "  Installed: Zeek + Suricata + Filebeat + coderedndr CLI"
  echo "  Services:  All stopped (start via coderedndr menu option 9)"
  echo ""

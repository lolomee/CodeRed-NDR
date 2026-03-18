#!/bin/bash
# CodeRed NDR - Deploy CodeRed Overlay
set -euo pipefail

echo "=== CodeRed Sensor Build: Step 3 - CodeRed Overlay ==="

CODERED_VERSION="${CODERED_VERSION:-1.0.0}"
CODERED_DIR="/opt/codered"

# Create directory structure
mkdir -p "${CODERED_DIR}"/{firstboot,shell,bin}
mkdir -p /etc/codered
mkdir -p /var/log/codered

# Copy files
echo "Installing CodeRed components..."

# Firstboot wizard
cp "${CODERED_DIR}/firstboot/"*.py "${CODERED_DIR}/firstboot/" 2>/dev/null || true
chmod 755 "${CODERED_DIR}/firstboot/wizard.py"

# Restricted shell
cp "${CODERED_DIR}/shell/"*.py "${CODERED_DIR}/shell/" 2>/dev/null || true
chmod 755 "${CODERED_DIR}/shell/menu.py"

# Default config
cp "${CODERED_DIR}/conf/codered.defaults" /etc/codered/codered.defaults

# Version file
echo "${CODERED_VERSION}" > "${CODERED_DIR}/VERSION"

# Install systemd services
cp "${CODERED_DIR}/firstboot/firstboot.service" /etc/systemd/system/codered-firstboot.service
systemctl daemon-reload
systemctl enable codered-firstboot.service

# Copy Salt states and pillars to SO local overlay directory
SO_SALT="/opt/so/saltstack/local"
if [ -d "$SO_SALT" ]; then
    echo "Installing Salt states..."
    cp -r "${CODERED_DIR}/salt/states/codered" "${SO_SALT}/salt/" 2>/dev/null || true
    cp -r "${CODERED_DIR}/salt/pillar/codered" "${SO_SALT}/pillar/" 2>/dev/null || true
else
    echo "WARNING: SO Salt directory not found at ${SO_SALT}"
    mkdir -p "${SO_SALT}/salt" "${SO_SALT}/pillar"
    cp -r "${CODERED_DIR}/salt/states/codered" "${SO_SALT}/salt/"
    cp -r "${CODERED_DIR}/salt/pillar/codered" "${SO_SALT}/pillar/"
fi

# Deploy restricted shell profile
cp "${CODERED_DIR}/shell/rbash_profile" /etc/profile.d/codered-menu.sh
chmod 644 /etc/profile.d/codered-menu.sh

echo "CodeRed overlay v${CODERED_VERSION} installed."

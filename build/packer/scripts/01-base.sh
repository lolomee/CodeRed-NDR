#!/bin/bash
# CodeRed NDR - Base System Setup
set -euo pipefail

echo "=== CodeRed Sensor Build: Step 1 - Base Packages ==="

# Update system
dnf update -y || apt-get update && apt-get upgrade -y

# Install essential packages
dnf install -y \
    dialog \
    python3 \
    python3-pip \
    python3-dialog \
    ethtool \
    net-tools \
    jq \
    git \
    curl \
    ufw \
    apparmor \
    apparmor-utils \
    fail2ban \
    rsyslog \
    2>/dev/null || \
apt-get install -y \
    dialog \
    python3 \
    python3-pip \
    python3-dialog \
    ethtool \
    net-tools \
    jq \
    git \
    curl \
    ufw \
    apparmor \
    apparmor-utils \
    fail2ban \
    rsyslog \
    2>/dev/null || true

echo "Base packages installed."

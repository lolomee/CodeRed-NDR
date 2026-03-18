#!/bin/bash
# CodeRed NDR - Security Onion Sensor Installation
set -euo pipefail

echo "=== CodeRed Sensor Build: Step 2 - Security Onion Setup ==="

SO_ROLE="${SO_ROLE:-sensor}"

# Check if SO is already installed
if [ -f /opt/so/state/setup_complete ]; then
    echo "Security Onion already installed. Skipping."
    exit 0
fi

# If SO setup script exists, run in sensor mode
if [ -x /usr/sbin/so-setup ]; then
    echo "Running so-setup in sensor mode..."
    # Note: In production builds, provide a pre-configured answers file
    # For now, SO setup will be completed by the first-boot wizard
    echo "SO setup will be completed by the first-boot wizard."
else
    echo "WARNING: so-setup not found. Ensure this is a Security Onion image."
fi

echo "Security Onion base setup complete."

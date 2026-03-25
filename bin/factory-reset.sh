#!/bin/bash
# CodeRed NDR - Factory Reset
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║         CodeRed NDR - FACTORY RESET              ║"
echo "║  This will erase all configuration and data!     ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
read -rp "Type 'RESET' to confirm: " CONFIRM
if [ "$CONFIRM" != "RESET" ]; then
    echo "Cancelled."
    exit 0
fi

echo "Stopping services..."
systemctl stop codered-zeek codered-suricata filebeat codered-pcap 2>/dev/null || true
systemctl disable codered-zeek codered-suricata filebeat codered-pcap 2>/dev/null || true

echo "Removing configuration..."
rm -f /etc/codered/sensor.conf
rm -f /etc/codered/.setup-complete
rm -f /var/lib/codered/.firstboot-complete

echo "Resetting Zeek config..."
cat > /opt/zeek/etc/node.cfg << 'EOF'
# CodeRed NDR - Zeek Node Configuration
# Interface is set by the first-boot wizard or CLI

[zeek]
type=standalone
host=localhost
interface=af_packet::__MONITOR_IF__
EOF

echo "Clearing data..."
rm -rf /nsm/zeek/logs/current/* /nsm/zeek/spool/* /nsm/zeek/extracted/*
rm -rf /nsm/suricata/log/*
rm -rf /nsm/pcap/*
truncate -s 0 /var/log/codered/*.log 2>/dev/null || true

echo "Resetting Filebeat..."
rm -f /etc/filebeat/filebeat.yml

echo ""
echo "Factory reset complete."
echo "Run the setup wizard on next login to reconfigure."
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) action=factory-reset" >> /var/log/codered/audit.log

#!/bin/bash
# CodeRed NDR - OVA Build Script (manual fallback)
# Usage: ./build-ova.sh [version]
# Preferred method: use Packer (build/packer/sensor.pkr.hcl)

set -euo pipefail

VERSION="${1:-$(cat ../VERSION 2>/dev/null || echo '1.0.0')}"
OUTPUT_DIR="$(pwd)/output"
VM_NAME="codered-sensor-${VERSION}"
DISK_SIZE="80G"
RAM="8192"
CPUS="4"

echo "╔══════════════════════════════════════════╗"
echo "║  CodeRed NDR OVA Builder v${VERSION}  ║"
echo "╚══════════════════════════════════════════╝"

# Check dependencies
for cmd in virt-install virsh qemu-img virt-sysprep; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install libvirt, qemu-utils, libguestfs-tools."
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

echo "[1/6] Creating VM disk..."
qemu-img create -f qcow2 "${OUTPUT_DIR}/${VM_NAME}.qcow2" "$DISK_SIZE"

echo "[2/6] Note: VM installation requires a Security Onion ISO."
echo "       Download from: https://securityonionsolutions.com/software"
echo ""
echo "  After SO installation, run the following on the VM:"
echo "    1. Copy codered-sensor/ to /opt/codered/"
echo "    2. Run: make install"
echo "    3. Run: salt-call --local state.apply codered"
echo ""

echo "[3/6] For automated builds, use Packer:"
echo "  cd build/packer && packer build sensor.pkr.hcl"
echo ""

echo "[4/6] To convert an existing VM to OVA:"
echo ""
echo "  # From qcow2:"
echo "  qemu-img convert -f qcow2 -O vmdk ${VM_NAME}.qcow2 ${VM_NAME}.vmdk"
echo "  # Then create OVF descriptor and tar into OVA"
echo ""
echo "  # From VirtualBox:"
echo "  VBoxManage export ${VM_NAME} -o ${OUTPUT_DIR}/${VM_NAME}.ova"
echo ""

echo "[5/6] Post-install cleanup (run on VM before export):"
cat << 'CLEANUP'
  # Remove SSH host keys (regenerated on first boot)
  rm -f /etc/ssh/ssh_host_*

  # Remove machine-id (regenerated on first boot)
  truncate -s 0 /etc/machine-id
  rm -f /var/lib/dbus/machine-id

  # Clear logs
  find /var/log -type f -name '*.log' -exec truncate -s 0 {} \;
  journalctl --vacuum-time=1s

  # Clear bash history
  rm -f /root/.bash_history /home/*/.bash_history

  # Clear temp files
  rm -rf /tmp/* /var/tmp/*

  # Zero free space for better compression
  dd if=/dev/zero of=/zero bs=1M 2>/dev/null || true
  rm -f /zero

  # Ensure firstboot will trigger
  rm -f /etc/codered/.setup-complete
CLEANUP

echo ""
echo "[6/6] Build complete. Follow the steps above to create your OVA."
echo "      For fully automated builds, use: cd build/packer && packer build sensor.pkr.hcl"

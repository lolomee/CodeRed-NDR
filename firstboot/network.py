"""Network configuration for management and monitoring interfaces."""

import logging
import subprocess
import shlex

logger = logging.getLogger('codered.network')


def apply_static_ip(interface: str, ip: str, netmask: str, gateway: str, dns: str) -> bool:
    """Apply static IP configuration using nmcli (NetworkManager)."""
    try:
        conn_name = f"codered-{interface}"

        # Delete existing connection if any
        subprocess.run(
            ['nmcli', 'connection', 'delete', conn_name],
            capture_output=True, timeout=15
        )

        # Create new static connection
        dns_servers = ' '.join(s.strip() for s in dns.split(','))
        subprocess.run([
            'nmcli', 'connection', 'add',
            'con-name', conn_name,
            'ifname', interface,
            'type', 'ethernet',
            'ipv4.method', 'manual',
            'ipv4.addresses', f'{ip}/{_netmask_to_cidr(netmask)}',
            'ipv4.gateway', gateway,
            'ipv4.dns', dns_servers,
            'connection.autoconnect', 'yes',
        ], check=True, capture_output=True, timeout=30)

        # Activate the connection
        subprocess.run(
            ['nmcli', 'connection', 'up', conn_name],
            check=True, capture_output=True, timeout=30
        )

        logger.info("Static IP %s/%s applied to %s", ip, netmask, interface)
        return True

    except subprocess.CalledProcessError as e:
        logger.error("Failed to apply static IP: %s", e.stderr.decode() if e.stderr else str(e))
        return False
    except subprocess.TimeoutExpired:
        logger.error("Timeout applying network config")
        return False


def apply_dhcp(interface: str) -> bool:
    """Configure interface for DHCP using nmcli."""
    try:
        conn_name = f"codered-{interface}"

        subprocess.run(
            ['nmcli', 'connection', 'delete', conn_name],
            capture_output=True, timeout=15
        )

        subprocess.run([
            'nmcli', 'connection', 'add',
            'con-name', conn_name,
            'ifname', interface,
            'type', 'ethernet',
            'ipv4.method', 'auto',
            'connection.autoconnect', 'yes',
        ], check=True, capture_output=True, timeout=30)

        subprocess.run(
            ['nmcli', 'connection', 'up', conn_name],
            check=True, capture_output=True, timeout=30
        )

        logger.info("DHCP configured on %s", interface)
        return True

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error("Failed to configure DHCP: %s", e)
        return False


def configure_monitor_interface(interface: str) -> bool:
    """Set monitoring interface to promiscuous mode with no IP."""
    try:
        # Bring up interface in promisc mode, no IP address
        subprocess.run(
            ['ip', 'link', 'set', interface, 'up', 'promisc', 'on'],
            check=True, capture_output=True, timeout=15
        )

        # Remove any existing IP addresses
        subprocess.run(
            ['ip', 'addr', 'flush', 'dev', interface],
            capture_output=True, timeout=15
        )

        # Disable offloading features for accurate packet capture
        for feature in ['rx', 'tx', 'sg', 'tso', 'ufo', 'gso', 'gro', 'lro']:
            subprocess.run(
                ['ethtool', '-K', interface, feature, 'off'],
                capture_output=True, timeout=10
            )

        # Create persistent NetworkManager config (unmanaged)
        conn_name = f"codered-monitor-{interface}"
        subprocess.run(
            ['nmcli', 'connection', 'delete', conn_name],
            capture_output=True, timeout=15
        )
        subprocess.run([
            'nmcli', 'connection', 'add',
            'con-name', conn_name,
            'ifname', interface,
            'type', 'ethernet',
            'ipv4.method', 'disabled',
            'ipv6.method', 'disabled',
            'connection.autoconnect', 'yes',
        ], check=True, capture_output=True, timeout=30)

        logger.info("Monitor interface %s configured (promisc, no IP)", interface)
        return True

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error("Failed to configure monitor interface: %s", e)
        return False


def set_hostname(hostname: str) -> bool:
    """Set system hostname."""
    try:
        subprocess.run(
            ['hostnamectl', 'set-hostname', hostname],
            check=True, capture_output=True, timeout=15
        )
        logger.info("Hostname set to %s", hostname)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error("Failed to set hostname: %s", e)
        return False


def _netmask_to_cidr(netmask: str) -> int:
    """Convert dotted netmask to CIDR prefix length."""
    if netmask.isdigit():
        return int(netmask)
    parts = netmask.split('.')
    binary = ''.join(format(int(p), '08b') for p in parts)
    return binary.count('1')

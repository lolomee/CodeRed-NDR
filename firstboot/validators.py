"""Input validators for first-boot wizard fields."""

import ipaddress
import re
import socket


def validate_hostname(hostname: str) -> tuple[bool, str]:
    """Validate RFC 1123 hostname."""
    if not hostname:
        return False, "Hostname cannot be empty"
    if len(hostname) > 253:
        return False, "Hostname too long (max 253 chars)"
    pattern = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$')
    if not pattern.match(hostname.lower()):
        return False, "Invalid hostname. Use only a-z, 0-9, hyphens. Must start/end with alphanumeric."
    return True, ""


def validate_ip(ip_str: str) -> tuple[bool, str]:
    """Validate IPv4 address."""
    if not ip_str:
        return False, "IP address cannot be empty"
    try:
        ipaddress.IPv4Address(ip_str)
        return True, ""
    except ipaddress.AddressValueError as e:
        return False, f"Invalid IPv4 address: {e}"


def validate_netmask(mask: str) -> tuple[bool, str]:
    """Validate subnet mask (dotted or CIDR prefix)."""
    if not mask:
        return False, "Netmask cannot be empty"
    # Accept CIDR notation
    if mask.isdigit():
        prefix = int(mask)
        if 1 <= prefix <= 32:
            return True, ""
        return False, "CIDR prefix must be 1-32"
    # Accept dotted notation
    try:
        parts = mask.split('.')
        if len(parts) != 4:
            raise ValueError("Must have 4 octets")
        val = 0
        for p in parts:
            val = (val << 8) | int(p)
        # Check it's a valid mask (contiguous 1s then 0s)
        inv = val ^ 0xFFFFFFFF
        if (inv + 1) & inv != 0:
            raise ValueError("Not a valid subnet mask")
        return True, ""
    except (ValueError, OverflowError) as e:
        return False, f"Invalid netmask: {e}"


def validate_dns(dns_str: str) -> tuple[bool, str]:
    """Validate comma-separated DNS servers."""
    if not dns_str:
        return False, "DNS servers cannot be empty"
    servers = [s.strip() for s in dns_str.split(',')]
    for srv in servers:
        ok, err = validate_ip(srv)
        if not ok:
            return False, f"DNS server '{srv}': {err}"
    return True, ""


def validate_interface(iface: str) -> tuple[bool, str]:
    """Validate network interface name."""
    if not iface:
        return False, "Interface name cannot be empty"
    pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9._\-]{0,14}$')
    if not pattern.match(iface):
        return False, "Invalid interface name"
    return True, ""


def validate_token(token: str) -> tuple[bool, str]:
    """Validate registration token (optional, but if set must be non-empty alphanum+hyphens)."""
    if not token:
        return True, ""  # Token is optional
    pattern = re.compile(r'^[a-zA-Z0-9\-_.]{4,256}$')
    if not pattern.match(token):
        return False, "Token must be 4-256 chars, alphanumeric with hyphens/underscores/dots"
    return True, ""


def validate_endpoint(endpoint: str) -> tuple[bool, str]:
    """Validate SIEM endpoint (hostname or IP)."""
    if not endpoint:
        return False, "SIEM endpoint cannot be empty"
    # Try as IP first
    ok, _ = validate_ip(endpoint)
    if ok:
        return True, ""
    # Try as hostname
    ok, err = validate_hostname(endpoint)
    if ok:
        return True, ""
    return False, f"Invalid endpoint. Must be a valid IP or hostname: {err}"


def validate_port(port_str: str) -> tuple[bool, str]:
    """Validate TCP port number."""
    if not port_str:
        return False, "Port cannot be empty"
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return True, ""
        return False, "Port must be 1-65535"
    except ValueError:
        return False, "Port must be a number"


def get_available_interfaces() -> list[str]:
    """Return list of available network interfaces (excluding lo)."""
    interfaces = []
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f.readlines()[2:]:  # Skip header lines
                iface = line.split(':')[0].strip()
                if iface and iface != 'lo':
                    interfaces.append(iface)
    except (IOError, OSError):
        pass
    return sorted(interfaces)

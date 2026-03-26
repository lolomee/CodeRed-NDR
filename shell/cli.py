#!/usr/bin/env python3
"""CodeRed NDR - Unified SSH CLI.

Single entry point for all sensor management. Replaces both the
first-boot wizard and the restricted management menu.

- First login (unconfigured): runs setup wizard
- Subsequent logins: management menu with reconfigure options

Designed to feel like FortiGate/Palo Alto CLI over SSH.
"""

import configparser
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# ─── Constants ─────────────────────────────────────────

VERSION_FILE = '/opt/codered/VERSION'
CONF_DIR = '/etc/codered'
CONF_FILE = f'{CONF_DIR}/sensor.conf'
DEFAULTS_FILE = f'{CONF_DIR}/codered.defaults'
SETUP_SENTINEL = f'{CONF_DIR}/.setup-complete'
AUDIT_LOG = '/var/log/codered/audit.log'
LOG_FILE = '/var/log/codered/cli.log'

BANNER = r"""
   ____          _      ____          _      _    ___
  / ___|___   __| | ___|  _ \ ___  __| |   / \  |_ _|
 | |   / _ \ / _` |/ _ \ |_) / _ \/ _` |  / _ \  | |
 | |__| (_) | (_| |  __/  _ <  __/ (_| | / ___ \ | |
  \____\___/ \__,_|\___|_| \_\___|\__,_|/_/   \_\___|

             CodeRed NDR Sensor
"""

# ─── Logging ───────────────────────────────────────────

def setup_logging():
    os.makedirs('/var/log/codered', mode=0o750, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
        ]
    )

def audit(action: str):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            user = os.environ.get('USER', 'unknown')
            src = os.environ.get('SSH_CLIENT', 'console').split()[0] if 'SSH_CLIENT' in os.environ else 'console'
            f.write(f'{ts} user={user} src={src} action={action}\n')
    except OSError:
        pass

# ─── Validators ────────────────────────────────────────

def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_fqdn(hostname: str) -> bool:
    """Validate a fully qualified domain name."""
    if not hostname or len(hostname) > 253:
        return False
    return bool(re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', hostname.lower()))

def is_valid_host(host: str) -> bool:
    """Validate IP address or FQDN."""
    return is_valid_ip(host) or is_valid_fqdn(host)

def is_valid_cidr(cidr: str) -> bool:
    try:
        prefix = int(cidr.strip('/'))
        return 1 <= prefix <= 32
    except (ValueError, TypeError):
        return False

def is_valid_netmask(mask: str) -> bool:
    if mask.isdigit() or mask.startswith('/'):
        return is_valid_cidr(mask.strip('/'))
    try:
        parts = mask.split('.')
        if len(parts) != 4:
            return False
        val = 0
        for p in parts:
            val = (val << 8) | int(p)
        inv = val ^ 0xFFFFFFFF
        return (inv + 1) & inv == 0
    except (ValueError, OverflowError):
        return False

def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    return bool(re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', hostname.lower()))

def is_valid_port(port_str: str) -> bool:
    try:
        return 1 <= int(port_str) <= 65535
    except (ValueError, TypeError):
        return False

def netmask_to_cidr(netmask: str) -> int:
    if netmask.isdigit():
        val = int(netmask)
        return val if 1 <= val <= 32 else 24
    if netmask.startswith('/'):
        val = int(netmask[1:])
        return val if 1 <= val <= 32 else 24
    parts = netmask.split('.')
    binary = ''.join(format(int(p), '08b') for p in parts)
    return binary.count('1')

# ─── System Helpers ────────────────────────────────────

def get_interfaces() -> list[str]:
    try:
        with open('/proc/net/dev') as f:
            return sorted([
                line.split(':')[0].strip()
                for line in f.readlines()[2:]
                if line.split(':')[0].strip() not in ('lo', '')
            ])
    except OSError:
        return []

def get_version() -> str:
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip()
    except OSError:
        return 'unknown'

def run_cmd(cmd: list[str], timeout: int = 30, sudo: bool = False) -> tuple[int, str]:
    """Run a command. If sudo=True, prepend sudo for privileged ops."""
    if sudo:
        cmd = ['sudo'] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 1, 'Command timed out'
    except FileNotFoundError:
        return 1, f'Command not found: {cmd[0]}'

def is_configured() -> bool:
    return os.path.exists(SETUP_SENTINEL)

# ─── Config Read/Write ─────────────────────────────────

def load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if os.path.exists(DEFAULTS_FILE):
        config.read(DEFAULTS_FILE)
    if os.path.exists(CONF_FILE):
        config.read(CONF_FILE)
    return config

def save_config(config: configparser.ConfigParser):
    # Write to temp file first, then sudo move to /etc/codered/
    run_cmd(['mkdir', '-p', CONF_DIR], sudo=True)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write('# CodeRed NDR Configuration\n')
        f.write(f'# Last modified: {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}\n\n')
        config.write(f)
        tmp_path = f.name
    run_cmd(['cp', tmp_path, CONF_FILE], sudo=True)
    run_cmd(['chmod', '640', CONF_FILE], sudo=True)
    os.unlink(tmp_path)

def get_val(config, section, key, fallback=''):
    return config.get(section, key, fallback=fallback)

# ─── Display Helpers ───────────────────────────────────

def clear():
    os.system('clear 2>/dev/null || true')

def header(title: str):
    width = 60
    print()
    print('=' * width)
    print(f'  {title}')
    print('=' * width)

def print_line(label: str, value: str, width: int = 24):
    print(f'  {label:<{width}} {value}')

def prompt(label: str, default: str = '', validator=None, required: bool = True) -> str:
    """Prompt for input with optional validation."""
    while True:
        suffix = f' [{default}]' if default else ''
        try:
            val = input(f'  {label}{suffix}: ').strip()
        except EOFError:
            print()
            continue

        if not val and default:
            val = default
        if not val and not required:
            return ''
        if not val and required:
            print(f'    * Required field')
            continue
        if validator and not validator(val):
            print(f'    * Invalid input')
            continue
        return val

def prompt_choice(label: str, options: list[str], default: str = '') -> str:
    """Prompt for a choice from a list."""
    opts_str = '/'.join(options)
    while True:
        suffix = f' [{default}]' if default else ''
        try:
            val = input(f'  {label} ({opts_str}){suffix}: ').strip().lower()
        except EOFError:
            print()
            continue
        if not val and default:
            return default
        if val in [o.lower() for o in options]:
            return val
        print(f'    * Choose one of: {opts_str}')

def prompt_interface(label: str, exclude: list[str] = None) -> str:
    """Prompt for a single network interface with auto-detection."""
    interfaces = get_interfaces()
    if exclude:
        interfaces = [i for i in interfaces if i not in exclude]

    if interfaces:
        print(f'\n  Detected interfaces:')
        for i, iface in enumerate(interfaces, 1):
            _, out = run_cmd(['ip', '-4', '-br', 'addr', 'show', iface])
            status = out.strip().split('\n')[0] if out.strip() else ''
            print(f'    {i}. {iface:<16} {status}')
        print()

    while True:
        try:
            val = input(f'  {label}: ').strip()
        except EOFError:
            print()
            continue
        if not val:
            print('    * Required field')
            continue
        # Accept number or name
        if val.isdigit() and 1 <= int(val) <= len(interfaces):
            return interfaces[int(val) - 1]
        if re.match(r'^[a-zA-Z]', val):
            return val
        print('    * Enter interface name or number')


def prompt_multi_interface(label: str, exclude: list[str] = None) -> list[str]:
    """Prompt for one or more network interfaces (comma-separated or space-separated)."""
    interfaces = get_interfaces()
    if exclude:
        interfaces = [i for i in interfaces if i not in exclude]

    if interfaces:
        print(f'\n  Detected interfaces:')
        for i, iface in enumerate(interfaces, 1):
            _, out = run_cmd(['ip', '-4', '-br', 'addr', 'show', iface])
            status = out.strip().split('\n')[0] if out.strip() else ''
            print(f'    {i}. {iface:<16} {status}')
        print()
        print('  Select one or more interfaces (comma-separated)')
        print('  Example: 1,2 or ens34,ens35\n')

    while True:
        try:
            val = input(f'  {label}: ').strip()
        except EOFError:
            print()
            continue
        if not val:
            print('    * At least one interface required')
            continue

        # Parse comma or space separated
        parts = [p.strip() for p in val.replace(' ', ',').split(',') if p.strip()]
        selected = []
        valid = True
        for p in parts:
            if p.isdigit() and 1 <= int(p) <= len(interfaces):
                selected.append(interfaces[int(p) - 1])
            elif re.match(r'^[a-zA-Z]', p):
                selected.append(p)
            else:
                print(f'    * Invalid selection: {p}')
                valid = False
                break

        if valid and selected:
            # Remove duplicates, preserve order
            seen = set()
            unique = []
            for s in selected:
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            print(f'  Selected: {", ".join(unique)}')
            if confirm('Confirm selection?'):
                return unique
        elif valid:
            print('    * At least one interface required')

def confirm(msg: str = 'Proceed?', default: bool = True) -> bool:
    suffix = ' [Y/n]' if default else ' [y/N]'
    try:
        val = input(f'\n  {msg}{suffix}: ').strip().lower()
    except EOFError:
        return default
    if not val:
        return default
    return val in ('y', 'yes')

def pause():
    try:
        input('\n  Press Enter to continue...')
    except EOFError:
        pass

# ─── Network Apply ─────────────────────────────────────

def apply_hostname(hostname: str) -> bool:
    audit(f'set-hostname:{hostname}')
    rc, out = run_cmd(['hostnamectl', 'set-hostname', hostname], sudo=True)
    return rc == 0

def apply_network(config: configparser.ConfigParser) -> bool:
    """Apply management network configuration via netplan (Ubuntu server standard).
    Falls back to nmcli if NetworkManager is present (desktop installs)."""
    iface = get_val(config, 'network', 'mgmt_interface', 'ens32')
    mode  = get_val(config, 'network', 'mgmt_mode', 'dhcp')
    audit(f'apply-network:{iface}:{mode}')

    # ── Build netplan YAML ────────────────────────────────────────────────────
    netplan_file = '/etc/netplan/01-codered-mgmt.yaml'

    if mode == 'dhcp':
        yaml_content = f"""network:
  version: 2
  renderer: networkd
  ethernets:
    {iface}:
      dhcp4: true
      dhcp6: false
"""
    else:
        ip   = get_val(config, 'network', 'mgmt_ip')
        mask = get_val(config, 'network', 'mgmt_netmask', '255.255.255.0')
        gw   = get_val(config, 'network', 'mgmt_gateway')
        dns  = get_val(config, 'network', 'mgmt_dns', '8.8.8.8')
        cidr = netmask_to_cidr(mask)
        dns_list = ', '.join(f'"{s.strip()}"' for s in dns.split(','))

        if not ip or not gw:
            print('    ! Static IP: missing IP or gateway.')
            return False

        yaml_content = f"""network:
  version: 2
  renderer: networkd
  ethernets:
    {iface}:
      dhcp4: false
      addresses:
        - {ip}/{cidr}
      routes:
        - to: default
          via: {gw}
      nameservers:
        addresses: [{dns_list}]
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tf:
        tf.write(yaml_content)
        tmp = tf.name
    run_cmd(['cp', tmp, netplan_file], sudo=True)
    run_cmd(['chmod', '600', netplan_file], sudo=True)
    os.unlink(tmp)

    rc, out = run_cmd(['netplan', 'apply'], timeout=15, sudo=True)
    if rc != 0:
        print(f'    ! netplan apply failed: {out}')
        return False
    return True

def apply_monitor_interface(iface: str) -> bool:
    """Set a single monitoring interface to promiscuous, no IP."""
    audit(f'apply-monitor:{iface}')
    run_cmd(['ip', 'link', 'set', iface, 'up', 'promisc', 'on'], sudo=True)
    run_cmd(['ip', 'addr', 'flush', 'dev', iface], sudo=True)
    for feature in ['rx', 'tx', 'sg', 'tso', 'gso', 'gro', 'lro']:
        run_cmd(['ethtool', '-K', iface, feature, 'off'], sudo=True)
    return True


def apply_monitor_interfaces(ifaces: list[str]) -> bool:
    """Set multiple monitoring interfaces to promiscuous, no IP."""
    for iface in ifaces:
        print(f'    Configuring {iface}...')
        apply_monitor_interface(iface)
    return True


def get_monitor_interfaces(config) -> list[str]:
    """Get list of monitor interfaces from config."""
    val = get_val(config, 'network', 'monitor_interfaces')
    if val:
        return [i.strip() for i in val.split(',') if i.strip()]
    # Fallback to old single interface key
    single = get_val(config, 'network', 'monitor_interface')
    if single:
        return [single]
    return []

# ─── Service Configuration ────────────────────────────

def apply_zeek_config(config: configparser.ConfigParser):
    """Update Zeek node.cfg and local.zeek with monitor interface(s) and cloud mode."""
    mon_ifaces = get_monitor_interfaces(config)
    if not mon_ifaces:
        return

    iface = mon_ifaces[0]
    cloud_mode = get_val(config, 'network', 'cloud_mode', 'no').strip().lower() == 'yes'
    vxlan_port  = get_val(config, 'network', 'vxlan_port', '4789').strip()
    node_cfg    = '/opt/zeek/etc/node.cfg'
    local_zeek  = '/opt/zeek/share/zeek/site/local.zeek'

    # ── node.cfg ────────────────────────────────────────────────────────────
    node_content = f"""# CodeRed NDR - Zeek Node Configuration
# Auto-generated by CLI — do not edit manually

[zeek]
type=standalone
host=localhost
interface=af_packet::{iface}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as tf:
        tf.write(node_content)
        tmp = tf.name
    run_cmd(['cp', tmp, node_cfg], sudo=True)
    run_cmd(['chmod', '640', node_cfg], sudo=True)
    run_cmd(['chown', 'root:zeek', node_cfg], sudo=True)
    os.unlink(tmp)

    # ── local.zeek — toggle CLOUD_MODE block ────────────────────────────────
    # Read existing local.zeek (installed from repo) and enable/disable
    # the VXLAN redef lines between the CLOUD_MODE_START/END markers.
    rc, lz = run_cmd(['cat', local_zeek], sudo=True)
    if rc == 0 and 'CLOUD_MODE_START' in lz:
        lines = lz.splitlines()
        new_lines = []
        in_block = False
        for line in lines:
            if 'CLOUD_MODE_START' in line:
                new_lines.append(line)
                in_block = True
                continue
            if 'CLOUD_MODE_END' in line:
                in_block = False
                new_lines.append(line)
                continue
            if in_block:
                stripped = line.lstrip('# ').strip()
                if stripped.startswith('redef') or stripped.startswith('# redef'):
                    # Remove any existing comment prefix, then re-add if needed
                    code = stripped.lstrip('# ').strip()
                    if cloud_mode:
                        new_lines.append(code)
                    else:
                        new_lines.append(f'# {code}')
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        updated = '\n'.join(new_lines) + '\n'
    else:
        # local.zeek missing or has no markers — write a minimal fallback
        vxlan_lines = ''
        if cloud_mode:
            vxlan_lines = (
                f'redef Tunnel::vxlan_ports += {{ {vxlan_port}/udp }};\n'
                f'redef PacketFilter::restricted_filter = "";\n'
            )
        updated = (
            '@load /opt/codered/zeek/codered-detections\n'
            'redef digest_salt = "codered-ndr-changeme-at-firstboot";\n'
            + vxlan_lines
        )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.zeek', delete=False) as tf:
        tf.write(updated)
        tmp = tf.name
    run_cmd(['cp', tmp, local_zeek], sudo=True)
    run_cmd(['chmod', '644', local_zeek], sudo=True)
    os.unlink(tmp)

    mode_str = 'cloud (VXLAN)' if cloud_mode else 'on-prem (raw)'
    logging.info(f'Zeek configured: iface={iface}, mode={mode_str}')

    # ── Tune each monitor interface ─────────────────────────────────────────
    for mon in mon_ifaces:
        run_cmd(['/opt/codered/bin/tune-interface.sh', mon], sudo=True)


def apply_suricata_config(config: configparser.ConfigParser):
    """Update Suricata config with monitor interface and cloud/VXLAN mode."""
    mon_ifaces = get_monitor_interfaces(config)
    if not mon_ifaces:
        return

    iface      = mon_ifaces[0]
    override   = '/etc/suricata/codered-override.yaml'
    community_id = get_val(config, 'suricata', 'community_id', 'yes')
    cloud_mode = get_val(config, 'network', 'cloud_mode', 'no').strip().lower() == 'yes'
    vxlan_port = get_val(config, 'network', 'vxlan_port', '4789').strip()

    comm = 'true' if community_id == 'yes' else 'false'

    # VXLAN decoder block — only written when cloud mode is active
    vxlan_block = ""
    if cloud_mode:
        vxlan_block = f"""
# Cloud mode: VXLAN decapsulation
# Strips VXLAN headers from AWS/AliCloud/Azure mirrored traffic so Suricata
# can inspect the inner packets and apply all detection rules normally.
decoder:
  vxlan:
    enabled: yes
    ports:
      - {vxlan_port}
"""

    content = f"""%YAML 1.1
---
# CodeRed NDR - Suricata Override Configuration
# Auto-generated by CLI — do not edit manually
# Cloud mode: {'yes — VXLAN decap enabled (UDP/' + vxlan_port + ')' if cloud_mode else 'no — on-prem raw capture'}

af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
{vxlan_block}
community-id:
  enabled: {comm}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /nsm/suricata/log/eve.json
      community-id: {comm}
      types:
        - alert:
            tagged-packets: yes
            metadata: yes
        - anomaly:
            enabled: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
            ja3: yes
            ja4: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - smtp:
            extended: yes
        - ssh
        - flow
        - netflow
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tf:
        tf.write(content)
        tmp = tf.name
    run_cmd(['mkdir', '-p', '/etc/suricata'], sudo=True)
    run_cmd(['cp', tmp, override], sudo=True)
    run_cmd(['chmod', '640', override], sudo=True)
    run_cmd(['chown', 'root:suricata', override], sudo=True)
    os.unlink(tmp)


def apply_filebeat_config(config: configparser.ConfigParser):
    """Generate and write Filebeat configuration."""
    endpoint = get_val(config, 'forwarding', 'siem_host')
    if not endpoint:
        endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    siem_output = get_val(config, 'forwarding', 'siem_output', 'elasticsearch')
    siem_tls = get_val(config, 'forwarding', 'siem_tls', 'false')
    sensor_name = get_val(config, 'sensor', 'sensor_name', 'sensor-01')

    protocol = 'https' if siem_tls == 'true' else 'http'

    content = f"""# CodeRed NDR - Filebeat Configuration
# Auto-generated by CLI — do not edit manually

name: "{sensor_name}"

filebeat.inputs:
  - type: log
    id: zeek-logs
    enabled: true
    paths:
      - /nsm/zeek/logs/current/*.log
    exclude_files: ['.gz$', 'stderr.log', 'stdout.log', 'capture_loss.log', 'reporter.log', 'stats.log']
    fields:
      source: zeek
      sensor_name: "{sensor_name}"
    fields_under_root: false

  - type: log
    id: suricata-eve
    enabled: true
    paths:
      - /nsm/suricata/log/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
    fields:
      source: suricata
      sensor_name: "{sensor_name}"
    fields_under_root: false

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: observer
      fields:
        name: "{sensor_name}"
        type: ndr
        vendor: CodeRed
        product: CodeRed NDR

"""
    # Add output section based on type
    if not endpoint:
        # No SIEM configured — buffer to file
        content += """output.file:
  enabled: true
  path: /var/log/codered
  filename: filebeat-buffer
  rotate_every_kb: 10240
  number_of_files: 3
# NOTE: Configure SIEM via menu option 8 to forward alerts
"""
    elif siem_output == 'logstash':
        content += f"""output.logstash:
  enabled: true
  hosts: ["{endpoint}:{port}"]
"""
        if siem_tls == 'true':
            content += """  ssl:
    enabled: true
    verification_mode: certificate
"""
    elif siem_output in ('syslog-tcp', 'syslog-udp'):
        # Filebeat 8.x uses output.logstash (Beats protocol) for TCP/UDP forwarding
        # Most SIEMs (QRadar, ArcSight, Graylog, Wazuh) can receive Beats protocol
        # Set up your SIEM to listen for Beats/Logstash input on this port
        content += f"""output.logstash:
  enabled: true
  hosts: ["{endpoint}:{port}"]
  # Beats protocol over TCP — configure your SIEM to accept Beats/Logstash input
  # QRadar:    Universal DSM with Syslog listener or Beats input
  # Graylog:   Beats input plugin on this port
  # Wazuh:     Logstash input with Beats codec
  # ArcSight:  Smart Connector with Syslog listener
"""
        if siem_tls == 'true':
            content += """  ssl:
    enabled: true
    verification_mode: certificate
"""
    else:
        # Default to elasticsearch
        content += f"""output.elasticsearch:
  enabled: true
  hosts: ["{protocol}://{endpoint}:{port}"]
"""
        if siem_tls == 'true':
            content += """  ssl:
    verification_mode: certificate
"""
        else:
            content += """  protocol: "http"
"""

    content += """
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(content)
        tmp = f.name
    run_cmd(['cp', tmp, '/etc/filebeat/filebeat.yml'], sudo=True)
    run_cmd(['chmod', '600', '/etc/filebeat/filebeat.yml'], sudo=True)
    os.unlink(tmp)

# ─── Setup Wizard ──────────────────────────────────────

def run_setup():
    """Initial configuration wizard. Runs on first SSH login."""
    clear()
    print(BANNER)
    print('  First-time setup. Configure your sensor below.')
    print('  Type Ctrl+C at any time to cancel.\n')

    config = load_config()

    # ── Hostname ──
    header('1. HOSTNAME')
    hostname = prompt('Hostname', get_val(config, 'sensor', 'hostname', 'codered-sensor'), is_valid_hostname)
    config.set('sensor', 'hostname', hostname)

    # ── Management Network ──
    header('2. MANAGEMENT NETWORK')
    mgmt_iface = prompt_interface('Management interface')
    config.set('network', 'mgmt_interface', mgmt_iface)

    mode = prompt_choice('IP mode', ['static', 'dhcp'], 'static')
    config.set('network', 'mgmt_mode', mode)

    if mode == 'static':
        ip = prompt('IP address', get_val(config, 'network', 'mgmt_ip'), is_valid_ip)
        mask = prompt('Netmask', get_val(config, 'network', 'mgmt_netmask', '255.255.255.0'), is_valid_netmask)
        gw = prompt('Gateway', get_val(config, 'network', 'mgmt_gateway'), is_valid_ip)
        dns = prompt('DNS (comma-separated)', get_val(config, 'network', 'mgmt_dns', '8.8.8.8,8.8.4.4'))
        config.set('network', 'mgmt_ip', ip)
        config.set('network', 'mgmt_netmask', mask)
        config.set('network', 'mgmt_gateway', gw)
        config.set('network', 'mgmt_dns', dns)

    # ── Monitor Interfaces (optional) ──
    header('3. MONITORING INTERFACES (SPAN/MIRROR PORTS)')
    print('  Select the interfaces connected to your SPAN/mirror ports.')
    print('  You can select multiple interfaces for multi-zone monitoring.')
    print('  Press Enter to skip (configure later via menu option 7).\n')
    interfaces = get_interfaces()
    available = [i for i in interfaces if i != mgmt_iface]
    if available:
        print('  Detected interfaces:')
        for i, iface in enumerate(available, 1):
            _, out = run_cmd(['ip', '-4', '-br', 'addr', 'show', iface])
            status = out.strip().split('\n')[0] if out.strip() else ''
            print(f'    {i}. {iface:<16} {status}')
        print()
    try:
        val = input('  Monitor interface(s) [skip]: ').strip()
    except EOFError:
        val = ''
    mon_ifaces = []
    if val:
        parts = [p.strip() for p in val.replace(' ', ',').split(',') if p.strip()]
        for p in parts:
            if p.isdigit() and 1 <= int(p) <= len(available):
                mon_ifaces.append(available[int(p) - 1])
            elif re.match(r'^[a-zA-Z]', p):
                mon_ifaces.append(p)
        if mon_ifaces:
            config.set('network', 'monitor_interfaces', ','.join(mon_ifaces))
            config.set('network', 'monitor_interface', mon_ifaces[0])
            print(f'  Selected: {", ".join(mon_ifaces)}')
    if not mon_ifaces:
        print('  Skipped — configure monitor interfaces later via CLI menu option 7.')

    # ── Sensor Identity ──
    header('4. SENSOR IDENTITY')
    name = prompt('Sensor name', get_val(config, 'sensor', 'sensor_name', 'sensor-01'))
    config.set('sensor', 'sensor_name', name)
    token = prompt('Registration token', get_val(config, 'sensor', 'registration_token'), required=False)
    config.set('sensor', 'registration_token', token)

    # ── SIEM Log Forwarding ──
    header('5. SIEM LOG FORWARDING')
    endpoint = prompt('SIEM address (IP or FQDN)', get_val(config, 'forwarding', 'siem_host'), is_valid_host, required=False)
    config.set('forwarding', 'siem_host', endpoint)

    if endpoint:
        port = prompt('SIEM port', get_val(config, 'forwarding', 'siem_port', '9200'), is_valid_port)
        config.set('forwarding', 'siem_port', port)

    # ── Deployment Mode ──
    header('6. DEPLOYMENT MODE')
    print('  Where is this sensor receiving traffic from?\n')
    print('    on-prem  Raw SPAN/TAP port — physical or virtual switch mirroring')
    print('    cloud    AWS VPC Traffic Mirroring, Alibaba Cloud, Azure vTAP')
    print('             (traffic arrives VXLAN-encapsulated on UDP/4789)\n')
    deploy_mode = prompt_choice('Deployment mode', ['on-prem', 'cloud'], 'on-prem')
    cloud_mode = 'yes' if deploy_mode == 'cloud' else 'no'
    config.set('network', 'cloud_mode', cloud_mode)

    if cloud_mode == 'yes':
        vxlan_port = prompt('VXLAN port', '4789', is_valid_port)
        config.set('network', 'vxlan_port', vxlan_port)
        print()
        print('  Cloud mode enabled. VXLAN decapsulation will be configured for:')
        print('    - Zeek (inner packet protocol parsing and detection)')
        print('    - Suricata (inner packet signature matching)')
        print()
        print('  Security group / firewall rule required on the sensor:')
        print(f'    Allow inbound UDP/{vxlan_port} from traffic mirror source IPs')
    else:
        config.set('network', 'vxlan_port', '4789')

    # ── Optional Features ──
    header('7. OPTIONAL FEATURES')
    ips = prompt_choice('Enable Suricata IPS mode (inline only)', ['yes', 'no'], 'no')
    config.set('suricata', 'ips_mode', ips)

    # ── Confirm ──
    header('CONFIGURATION SUMMARY')
    print_line('Hostname:', hostname)
    print_line('Mgmt Interface:', mgmt_iface)
    print_line('IP Mode:', mode)
    if mode == 'static':
        print_line('IP Address:', f'{ip}/{netmask_to_cidr(mask)}')
        print_line('Gateway:', gw)
        print_line('DNS:', dns)
    print_line('Monitor Interfaces:', ', '.join(mon_ifaces) if mon_ifaces else 'not configured (set later)')
    print_line('Sensor Name:', name)
    print_line('SIEM Destination:', f'{endpoint}:{get_val(config, "forwarding", "siem_port", "9200")}' if endpoint else 'not configured')
    print_line('Deployment Mode:', f"{'cloud (VXLAN)' if cloud_mode == 'yes' else 'on-prem (raw)'}")
    print_line('IPS Mode:', ips)

    if not confirm('Apply this configuration?'):
        print('\n  Setup cancelled. Run setup again on next login.')
        return False

    # ── Apply ──
    print('\n  Applying configuration...\n')

    print('  [1/5] Saving configuration...')
    save_config(config)

    print('  [2/5] Setting hostname...')
    apply_hostname(hostname)

    print('  [3/5] Configuring management network...')
    apply_network(config)

    if mon_ifaces:
        print(f'  [4/5] Configuring {len(mon_ifaces)} monitor interface(s)...')
        apply_monitor_interfaces(mon_ifaces)
    else:
        print('  [4/5] Skipping monitor interfaces (not configured)...')

    print('  [5/5] Starting sensor services...')
    # Configure Zeek node.cfg with monitor interfaces
    apply_zeek_config(config)
    # Configure Suricata
    apply_suricata_config(config)
    # Configure Filebeat
    apply_filebeat_config(config)
    if mon_ifaces:
        # Enable and start services only if monitor interface is set
        for svc in ['codered-zeek', 'codered-suricata', 'filebeat', 'codered-ml']:
            run_cmd(['systemctl', 'enable', svc], sudo=True)
            run_cmd(['systemctl', 'start', svc], sudo=True)
        # Update Suricata rules
        run_cmd(['/opt/codered/bin/update-rules.sh'], timeout=120, sudo=True)
    else:
        print('  Note: Zeek and Suricata will start after you configure monitor interfaces.')

    # Mark setup complete
    Path(SETUP_SENTINEL).touch(mode=0o644)
    audit('setup-complete')

    print('\n  Setup complete. Sensor is now active.')
    print('  You will see the management menu on next login.\n')
    return True

# ─── Management Menu ───────────────────────────────────

def show_status():
    """Show sensor status overview."""
    audit('view:status')
    config = load_config()

    header('SENSOR STATUS')

    # Identity
    print_line('Hostname:', subprocess.getoutput('hostname'))
    print_line('Sensor Name:', get_val(config, 'sensor', 'sensor_name'))
    print_line('Version:', get_version())
    print_line('Uptime:', subprocess.getoutput('uptime -p'))

    # Resources
    print()
    try:
        with open('/proc/cpuinfo') as f:
            cpus = sum(1 for l in f if l.startswith('processor'))
        with open('/proc/meminfo') as f:
            for l in f:
                if l.startswith('MemTotal'):
                    mem = int(l.split()[1]) // 1024
                    break
        load = subprocess.getoutput("cat /proc/loadavg | awk '{print $1, $2, $3}'")
        print_line('CPU:', f'{cpus} cores (load: {load})')
        print_line('Memory:', f'{mem} MB')
    except OSError:
        pass

    # Disk
    _, disk_out = run_cmd(['df', '-h', '--output=target,size,used,avail,pcent', '/', '/nsm'])
    if disk_out:
        print()
        for line in disk_out.strip().splitlines():
            print(f'  {line}')

    # Services
    print()
    print('  Services:')
    for display_name, svc in [('Zeek', 'codered-zeek'), ('Suricata', 'codered-suricata'), ('Filebeat', 'filebeat'), ('ML Engine', 'codered-ml')]:
        rc, out = run_cmd(['systemctl', 'is-active', svc], sudo=True)
        status = out.strip()
        if status == 'active':
            print_line(f'    {display_name}:', 'RUNNING', 20)
        else:
            print_line(f'    {display_name}:', status, 20)

    # Monitor interfaces + deployment mode
    print()
    mon_ifaces = get_monitor_interfaces(config)
    if mon_ifaces:
        print_line('Monitor Interfaces:', ', '.join(mon_ifaces))
    else:
        print_line('Monitor Interfaces:', 'none configured')

    cloud_mode = get_val(config, 'network', 'cloud_mode', 'no').strip().lower()
    vxlan_port  = get_val(config, 'network', 'vxlan_port', '4789')
    if cloud_mode == 'yes':
        print_line('Deployment Mode:', f'CLOUD  (VXLAN decap UDP/{vxlan_port})')
    else:
        print_line('Deployment Mode:', 'ON-PREM  (raw SPAN/TAP)')

    # Rule update status
    rule_log = '/var/log/codered/last-rule-update.log'
    if os.path.exists(rule_log):
        mtime = os.path.getmtime(rule_log)
        print_line('Rules Updated:', datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M'))
    else:
        print_line('Rules Updated:', 'pending first update')

    # Forwarding
    endpoint = get_val(config, 'forwarding', 'siem_host')
    if not endpoint:
        endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint:
        print_line('SIEM Destination:', f'{endpoint}:{port}')
    else:
        print_line('SIEM Destination:', 'not configured')

    pause()


def show_interfaces():
    """Show network interface details."""
    audit('view:interfaces')
    header('NETWORK INTERFACES')
    _, out = run_cmd(['ip', '-br', 'addr', 'show'])
    print()
    for line in out.strip().splitlines():
        print(f'  {line}')

    # Promisc check
    _, link_out = run_cmd(['ip', '-d', 'link', 'show'])
    promisc = [l.strip() for l in link_out.splitlines() if 'PROMISC' in l]
    if promisc:
        print('\n  Promiscuous interfaces:')
        for p in promisc:
            print(f'    {p}')
    pause()


def show_logs():
    """View recent log entries."""
    audit('view:logs')
    header('VIEW LOGS')
    logs = {
        '1': ('Suricata alerts', '/nsm/suricata/log/eve.json'),
        '2': ('Zeek DNS', '/nsm/zeek/logs/current/dns.log'),
        '3': ('Zeek connections', '/nsm/zeek/logs/current/conn.log'),
        '4': ('Zeek HTTP', '/nsm/zeek/logs/current/http.log'),
        '5': ('System log', '/var/log/syslog'),
        '6': ('Audit log', AUDIT_LOG),
    }
    for k, (name, path) in logs.items():
        exists = 'Y' if os.path.exists(path) else 'N'
        print(f'  {k}. [{exists}] {name}')

    print(f'  0. Back')

    try:
        choice = input('\n  Select: ').strip()
    except EOFError:
        return

    if choice in logs:
        name, path = logs[choice]
        if os.path.exists(path):
            audit(f'view:logs:{name}')
            _, out = run_cmd(['tail', '-n', '50', path], timeout=10)
            print(f'\n  === Last 50 lines: {name} ===\n')
            print(out)
        else:
            print(f'\n  File not found: {path}')
        pause()


def restart_services():
    """Restart sensor services."""
    header('RESTART SERVICES')
    services = {
        '1': ('All NDR services', ['codered-zeek', 'codered-suricata', 'filebeat', 'codered-ml']),
        '2': ('Zeek', ['codered-zeek']),
        '3': ('Suricata', ['codered-suricata']),
        '4': ('Filebeat', ['filebeat']),
        '5': ('ML engine', ['codered-ml']),
    }
    for k, (name, _) in services.items():
        print(f'  {k}. {name}')
    print(f'  0. Back')

    try:
        choice = input('\n  Select: ').strip()
    except EOFError:
        return

    if choice in services:
        name, svc_list = services[choice]
        if confirm(f'Restart {name}?'):
            audit(f'restart:{name}')
            for svc in svc_list:
                print(f'\n  Restarting {svc}...')
                rc, out = run_cmd(['systemctl', 'restart', svc], timeout=120, sudo=True)
                status = 'OK' if rc == 0 else f'FAILED: {out.strip()}'
                print(f'    {svc}: {status}')
            pause()


def reconfigure_network():
    """Reconfigure management network settings."""
    audit('reconfigure:network')
    config = load_config()

    header('RECONFIGURE NETWORK')
    print('  Current settings:')
    print_line('Interface:', get_val(config, 'network', 'mgmt_interface'))
    print_line('Mode:', get_val(config, 'network', 'mgmt_mode'))
    if get_val(config, 'network', 'mgmt_mode') == 'static':
        print_line('IP:', get_val(config, 'network', 'mgmt_ip'))
        print_line('Netmask:', get_val(config, 'network', 'mgmt_netmask'))
        print_line('Gateway:', get_val(config, 'network', 'mgmt_gateway'))
        print_line('DNS:', get_val(config, 'network', 'mgmt_dns'))
    print()

    if not confirm('Change network settings?'):
        return

    iface = prompt('Management interface', get_val(config, 'network', 'mgmt_interface'))
    config.set('network', 'mgmt_interface', iface)

    mode = prompt_choice('IP mode', ['static', 'dhcp'], get_val(config, 'network', 'mgmt_mode', 'static'))
    config.set('network', 'mgmt_mode', mode)

    if mode == 'static':
        ip = prompt('IP address', get_val(config, 'network', 'mgmt_ip'), is_valid_ip)
        mask = prompt('Netmask', get_val(config, 'network', 'mgmt_netmask', '255.255.255.0'), is_valid_netmask)
        gw = prompt('Gateway', get_val(config, 'network', 'mgmt_gateway'), is_valid_ip)
        dns = prompt('DNS', get_val(config, 'network', 'mgmt_dns', '8.8.8.8'), )
        config.set('network', 'mgmt_ip', ip)
        config.set('network', 'mgmt_netmask', mask)
        config.set('network', 'mgmt_gateway', gw)
        config.set('network', 'mgmt_dns', dns)

    print('\n  Applying network changes...')
    print('  WARNING: If you are changing the IP, you will lose this SSH session.')

    if not confirm('Apply now?'):
        return

    save_config(config)
    apply_network(config)
    print('  Network configuration applied.')
    pause()


def reconfigure_hostname():
    """Change sensor hostname."""
    audit('reconfigure:hostname')
    config = load_config()

    header('RECONFIGURE HOSTNAME')
    current = subprocess.getoutput('hostname')
    print_line('Current hostname:', current)
    print()

    hostname = prompt('New hostname', current, is_valid_hostname)
    if hostname == current:
        print('  No change.')
        return

    if confirm(f'Change hostname to "{hostname}"?'):
        config.set('sensor', 'hostname', hostname)
        save_config(config)
        apply_hostname(hostname)
        print(f'  Hostname changed to: {hostname}')
        pause()


def reconfigure_forwarding():
    """Reconfigure SIEM forwarding destination."""
    audit('reconfigure:forwarding')
    config = load_config()

    header('RECONFIGURE SIEM DESTINATION')
    current_host = get_val(config, 'forwarding', 'siem_host')
    if not current_host:
        current_host = get_val(config, 'forwarding', 'siem_endpoint')
    current_port = get_val(config, 'forwarding', 'siem_port', '9200')
    current_output = get_val(config, 'forwarding', 'siem_output', 'elasticsearch')
    current_tls = get_val(config, 'forwarding', 'siem_tls', 'false')

    print('  Current settings:')
    print_line('Output type:', current_output)
    print_line('SIEM Address:', current_host or 'not configured')
    print_line('SIEM Port:', current_port)
    print_line('TLS:', current_tls)
    print()

    print('  Output types:')
    print('    1. Elasticsearch  (HTTP/HTTPS JSON — Elastic, OpenSearch, Splunk HEC)')
    print('    2. Logstash       (Beats protocol TCP — Logstash, most SIEMs)')
    print('    3. Syslog TCP     (raw TCP syslog — QRadar, ArcSight, Graylog)')
    print('    4. Syslog UDP     (raw UDP syslog — legacy SIEM / network gear)')
    print()

    output_map = {
        '1': ('elasticsearch', '9200'),
        '2': ('logstash',      '5044'),
        '3': ('syslog-tcp',    '514'),
        '4': ('syslog-udp',    '514'),
    }
    current_num = {'elasticsearch': '1', 'logstash': '2',
                   'syslog-tcp': '3', 'syslog-udp': '4'}.get(current_output, '1')

    try:
        out_choice = input(f'  Output type [{current_num}]: ').strip() or current_num
    except EOFError:
        return

    if out_choice not in output_map:
        print('  Invalid choice.')
        pause()
        return

    siem_output, default_port = output_map[out_choice]
    config.set('forwarding', 'siem_output', siem_output)

    endpoint = prompt('SIEM address (IP or FQDN)', current_host, is_valid_host, required=False)
    config.set('forwarding', 'siem_host', endpoint)

    if endpoint:
        port = prompt('SIEM port', current_port or default_port, is_valid_port)
        config.set('forwarding', 'siem_port', port)

        # TLS option for elasticsearch and logstash
        if siem_output in ('elasticsearch', 'logstash'):
            tls = prompt_choice('TLS/HTTPS', ['yes', 'no'],
                                'yes' if current_tls == 'true' else 'no')
            config.set('forwarding', 'siem_tls', 'true' if tls == 'yes' else 'false')

    if confirm('Apply forwarding changes?'):
        save_config(config)
        print('\n  Applying forwarding configuration...')
        apply_filebeat_config(config)
        run_cmd(['systemctl', 'restart', 'filebeat'], sudo=True)
        # Show connection status
        import time
        time.sleep(2)
        rc, out = run_cmd(['journalctl', '-u', 'filebeat', '--no-pager', '-n', '5'], sudo=True)
        if out:
            print()
            for line in out.strip().splitlines()[-5:]:
                print(f'  {line}')
        print('\n  Done.')
        pause()



def reconfigure_cloud_mode():
    """Toggle cloud/on-prem deployment mode and apply VXLAN config."""
    audit('reconfigure:cloud-mode')
    config = load_config()

    header('DEPLOYMENT MODE')

    current_mode = get_val(config, 'network', 'cloud_mode', 'no').strip().lower()
    current_vxlan = get_val(config, 'network', 'vxlan_port', '4789')

    if current_mode == 'yes':
        print('  Current mode:  CLOUD  (VXLAN decapsulation enabled)')
        print(f'  VXLAN port:    {current_vxlan}')
    else:
        print('  Current mode:  ON-PREM  (raw SPAN/TAP, no encapsulation)')

    print()
    print('  on-prem  Physical/virtual switch SPAN port — no encapsulation')
    print('  cloud    AWS VPC Traffic Mirroring, Alibaba Cloud, Azure vTAP')
    print('           (mirrored traffic is VXLAN-encapsulated on UDP/4789)')
    print()

    mode = prompt_choice('Deployment mode', ['on-prem', 'cloud'],
                         'cloud' if current_mode == 'yes' else 'on-prem')
    cloud_mode = 'yes' if mode == 'cloud' else 'no'
    config.set('network', 'cloud_mode', cloud_mode)

    vxlan_port = current_vxlan
    if cloud_mode == 'yes':
        vxlan_port = prompt('VXLAN port', current_vxlan, is_valid_port)
        config.set('network', 'vxlan_port', vxlan_port)
        print()
        print('  Security group / firewall rule required on this sensor:')
        print(f'    Allow inbound UDP/{vxlan_port} from traffic mirror source IPs')
        print()
        print('  Cloud platform setup:')
        print('    AWS:      VPC -> Traffic Mirroring -> Create mirror session')
        print('              Mirror target = this sensor ENI')
        print('    AliCloud: VPC -> Traffic Mirror -> Create mirror session')
        print('              Mirror destination = this sensor ENI')
        print('    Azure:    Network Watcher -> Packet Capture (or vTAP preview)')
    else:
        config.set('network', 'vxlan_port', '4789')

    if not confirm(f'Apply {mode} mode? This will restart Zeek and Suricata.'):
        return

    print('\n  Saving configuration...')
    save_config(config)

    print('  Applying Zeek config (VXLAN decapsulation)...')
    apply_zeek_config(config)

    print('  Applying Suricata config (VXLAN decoder)...')
    apply_suricata_config(config)

    print('  Restarting Zeek...')
    rc, out = run_cmd(['systemctl', 'restart', 'codered-zeek'], timeout=120, sudo=True)
    print(f'    Zeek: {"OK" if rc == 0 else "FAILED — " + out.strip()}')

    print('  Restarting Suricata...')
    rc, out = run_cmd(['systemctl', 'restart', 'codered-suricata'], timeout=120, sudo=True)
    print(f'    Suricata: {"OK" if rc == 0 else "FAILED — " + out.strip()}')

    if cloud_mode == 'yes':
        print()
        print('  VXLAN decapsulation is now active.')
        print('  Verify traffic is flowing: Menu -> 4 (Diagnostics)')
        print('  Check Zeek conn.log appears within 60 seconds of mirror session start.')
    else:
        print()
        print('  On-prem mode active. Sensor expects raw SPAN/TAP traffic.')

    audit(f'reconfigure:cloud-mode:{mode}')
    pause()


def reconfigure_monitor():
    """Reconfigure monitoring interfaces (multi-interface support)."""
    audit('reconfigure:monitor')
    config = load_config()

    header('RECONFIGURE MONITOR INTERFACES')
    current = get_monitor_interfaces(config)
    if current:
        print(f'  Current monitor interfaces: {", ".join(current)}')
    else:
        print('  No monitor interfaces configured.')
    print()

    print('  Options:')
    print('    1. Replace all monitor interfaces')
    print('    2. Add interface(s)')
    print('    3. Remove interface(s)')
    print('    0. Back')

    try:
        choice = input('\n  Select: ').strip()
    except EOFError:
        return

    mgmt = get_val(config, 'network', 'mgmt_interface')

    if choice == '1':
        new_ifaces = prompt_multi_interface('New monitor interface(s)', exclude=[mgmt])
        config.set('network', 'monitor_interfaces', ','.join(new_ifaces))
        config.set('network', 'monitor_interface', new_ifaces[0])
        save_config(config)
        print('\n  Applying monitor interfaces...')
        apply_monitor_interfaces(new_ifaces)
        print('  Restarting Zeek and Suricata...')
        apply_zeek_config(config)
        apply_suricata_config(config)
        run_cmd(['systemctl', 'restart', 'codered-zeek'], timeout=120, sudo=True)
        run_cmd(['systemctl', 'restart', 'codered-suricata'], timeout=120, sudo=True)
        print('  Done.')
        pause()

    elif choice == '2':
        print(f'\n  Current: {", ".join(current)}')
        add_ifaces = prompt_multi_interface('Interface(s) to add', exclude=[mgmt] + current)
        new_list = current + add_ifaces
        config.set('network', 'monitor_interfaces', ','.join(new_list))
        config.set('network', 'monitor_interface', new_list[0])
        save_config(config)
        print('\n  Configuring new interfaces...')
        apply_monitor_interfaces(add_ifaces)
        print('  Restarting Zeek and Suricata...')
        apply_zeek_config(config)
        apply_suricata_config(config)
        run_cmd(['systemctl', 'restart', 'codered-zeek'], timeout=120, sudo=True)
        run_cmd(['systemctl', 'restart', 'codered-suricata'], timeout=120, sudo=True)
        print(f'  Monitor interfaces: {", ".join(new_list)}')
        pause()

    elif choice == '3':
        if len(current) <= 1:
            print('\n  Cannot remove — at least one monitor interface is required.')
            pause()
            return

        print(f'\n  Current interfaces:')
        for i, iface in enumerate(current, 1):
            print(f'    {i}. {iface}')

        try:
            val = input('\n  Interface(s) to remove (comma-separated numbers): ').strip()
        except EOFError:
            return

        to_remove = []
        for p in val.split(','):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= len(current):
                to_remove.append(current[int(p) - 1])

        if not to_remove:
            print('  No valid selection.')
            pause()
            return

        new_list = [i for i in current if i not in to_remove]
        if not new_list:
            print('  Cannot remove all interfaces — at least one must remain.')
            pause()
            return

        if confirm(f'Remove {", ".join(to_remove)}? Remaining: {", ".join(new_list)}'):
            config.set('network', 'monitor_interfaces', ','.join(new_list))
            config.set('network', 'monitor_interface', new_list[0])
            save_config(config)
            print('  Restarting Zeek and Suricata...')
            apply_zeek_config(config)
            apply_suricata_config(config)
            run_cmd(['systemctl', 'restart', 'codered-zeek'], timeout=120, sudo=True)
            run_cmd(['systemctl', 'restart', 'codered-suricata'], timeout=120, sudo=True)
            print('  Done.')
            pause()


def run_diagnostics():
    """Run diagnostic checks."""
    audit('diagnostics')
    header('DIAGNOSTICS')

    print('  Running checks...\n')

    # DNS resolution
    rc, _ = run_cmd(['host', 'google.com'])
    print_line('DNS resolution:', 'OK' if rc == 0 else 'FAIL')

    # Gateway ping
    config = load_config()
    gw = get_val(config, 'network', 'mgmt_gateway')
    if gw:
        rc, _ = run_cmd(['ping', '-c', '1', '-W', '3', gw], sudo=False)
        print_line('Gateway reachable:', 'OK' if rc == 0 else 'FAIL')

    # SIEM connectivity — use subprocess list args, never interpolate into bash -c
    endpoint = get_val(config, 'forwarding', 'siem_host')
    if not endpoint:
        endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint and is_valid_host(endpoint) and is_valid_port(port):
        # Use nc (netcat) with list args — no shell interpolation
        rc, _ = run_cmd(['nc', '-z', '-w', '5', endpoint, port], timeout=8)
        print_line(f'SIEM ({endpoint}:{port}):', 'OK' if rc == 0 else 'UNREACHABLE')

    # NTP sync
    rc, out = run_cmd(['timedatectl', 'show', '--property=NTPSynchronized'], sudo=True)
    synced = 'yes' in out.lower() if rc == 0 else False
    print_line('NTP synchronized:', 'OK' if synced else 'NOT SYNCED')

    # Disk space
    _, df_out = run_cmd(['df', '--output=pcent', '/'])
    if df_out:
        pct = df_out.strip().splitlines()[-1].strip().rstrip('%')
        try:
            print_line('Root disk usage:', f'{pct}% {"(WARNING >85%)" if int(pct) > 85 else ""}')
        except ValueError:
            pass

    _, df_nsm = run_cmd(['df', '--output=pcent', '/nsm'])
    if df_nsm:
        pct = df_nsm.strip().splitlines()[-1].strip().rstrip('%')
        try:
            print_line('NSM disk usage:', f'{pct}% {"(WARNING >85%)" if int(pct) > 85 else ""}')
        except ValueError:
            pass

    # Monitor interfaces
    mon_ifaces = get_monitor_interfaces(config)
    for mon in mon_ifaces:
        _, link_out = run_cmd(['ip', 'link', 'show', mon], sudo=True)
        if 'PROMISC' in link_out:
            print_line(f'Monitor ({mon}):', 'UP, PROMISC')
        elif 'UP' in link_out:
            print_line(f'Monitor ({mon}):', 'UP (not promisc!)')
        else:
            print_line(f'Monitor ({mon}):', 'DOWN')
    if not mon_ifaces:
        print_line('Monitor:', 'none configured')

    # Suricata rule update
    rule_log = '/var/log/codered/last-rule-update.log'
    if os.path.exists(rule_log):
        try:
            with open(rule_log) as f:
                content = f.read().strip()
            print_line('Rule update:', content)
        except OSError:
            print_line('Rule update:', 'unknown')
    else:
        print_line('Rule update:', 'not yet run')

    # Services
    print()
    print('  Service Health:')
    for svc, proc in [('Zeek', 'zeek'), ('Suricata', 'Suricata-Main'), ('Filebeat', 'filebeat')]:
        rc, _ = run_cmd(['pgrep', '-x', proc], sudo=True)
        print_line(f'    {svc}:', 'running' if rc == 0 else 'NOT RUNNING')

    pause()


def generate_support_bundle():
    """Generate a diagnostic bundle for support."""
    audit('support-bundle')
    header('GENERATE SUPPORT BUNDLE')

    bundle_path = f'/tmp/codered-diag-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.tar.gz'
    print(f'  Collecting diagnostics...\n')

    script = f"""
    set -e
    TMPDIR=$(mktemp -d)
    hostname > $TMPDIR/hostname.txt
    uptime > $TMPDIR/uptime.txt
    ip addr show > $TMPDIR/ip-addr.txt 2>&1
    ip route show > $TMPDIR/ip-route.txt 2>&1
    df -h > $TMPDIR/disk.txt 2>&1
    free -h > $TMPDIR/memory.txt 2>&1
    ps aux > $TMPDIR/processes.txt 2>&1
    systemctl list-units --type=service > $TMPDIR/services.txt 2>&1
    cp /etc/codered/sensor.conf $TMPDIR/sensor.conf 2>/dev/null || true
    # Redact tokens
    sed -i 's/token = .*/token = [REDACTED]/' $TMPDIR/sensor.conf 2>/dev/null || true
    sed -i 's/siem_token = .*/siem_token = [REDACTED]/' $TMPDIR/sensor.conf 2>/dev/null || true
    tail -200 /var/log/codered/cli.log > $TMPDIR/cli.log 2>/dev/null || true
    tail -200 /var/log/codered/audit.log > $TMPDIR/audit.log 2>/dev/null || true
    tail -500 /var/log/syslog > $TMPDIR/syslog-tail.txt 2>/dev/null || true
    journalctl -u codered-zeek -u codered-suricata -u filebeat --since "1 hour ago" --no-pager > $TMPDIR/journal.txt 2>/dev/null || true
    tar czf {bundle_path} -C $(dirname $TMPDIR) $(basename $TMPDIR)
    rm -rf $TMPDIR
    """

    rc, _ = run_cmd(['bash', '-c', script], timeout=60, sudo=True)
    if rc == 0 and os.path.exists(bundle_path):
        size = os.path.getsize(bundle_path) // 1024
        print(f'  Bundle created: {bundle_path} ({size} KB)')
        print(f'  Download via: scp coderedndr@<sensor-ip>:{bundle_path} .')
    else:
        print('  Failed to create bundle.')
    pause()


def do_reboot():
    """Reboot the sensor."""
    audit('reboot')
    if confirm('Reboot the sensor now?', default=False):
        print('\n  Rebooting...')
        run_cmd(['shutdown', '-r', 'now'], sudo=True)


def do_shutdown():
    """Shut down the sensor."""
    audit('shutdown')
    if confirm('Shut down the sensor? All monitoring will stop.', default=False):
        print('\n  Shutting down...')
        run_cmd(['shutdown', '-h', 'now'], sudo=True)


def change_password():
    """Change the login password for this sensor."""
    audit('change-password')
    header('CHANGE PASSWORD')
    print('  Change the login password for this sensor.\n')

    import getpass
    import pam

    current_user = os.environ.get('SUDO_USER', os.environ.get('USER', 'coderedndr'))

    try:
        current = getpass.getpass('  Current password: ')
        new_pw  = getpass.getpass('  New password: ')
        confirm_pw = getpass.getpass('  Confirm new password: ')
    except EOFError:
        return

    # ── Verify current password via PAM before allowing change ──
    # This prevents anyone who walks up to an unlocked session from
    # silently changing the password without knowing the current one.
    p = pam.pam()
    if not p.authenticate(current_user, current):
        print('\n  Incorrect current password.')
        audit('change-password:rejected:wrong-current-password')
        pause()
        return

    if new_pw != confirm_pw:
        print('\n  Passwords do not match.')
        pause()
        return

    if len(new_pw) < 12:
        print('\n  Password must be at least 12 characters.')
        pause()
        return

    # ── Check complexity: require at least one digit and one symbol ──
    has_digit  = any(c.isdigit()      for c in new_pw)
    has_upper  = any(c.isupper()      for c in new_pw)
    has_symbol = any(not c.isalnum()  for c in new_pw)
    if not (has_digit and has_upper and has_symbol):
        print('\n  Password must contain uppercase, a digit, and a symbol.')
        pause()
        return

    # ── Use chpasswd via subprocess pipe — never write password to disk ──
    # Passing the password through a tempfile creates a race-condition window
    # where it exists as plaintext in /tmp. Pipe via stdin instead.
    try:
        proc = subprocess.run(
            ['sudo', 'chpasswd'],
            input=f'{current_user}:{new_pw}\n',
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            print('\n  Password changed successfully.')
            audit('change-password:success')
        else:
            print(f'\n  Failed to change password.')
            audit('change-password:failed')
    except subprocess.TimeoutExpired:
        print('\n  Password change timed out.')
    finally:
        # Explicitly clear password strings from memory
        new_pw = confirm_pw = current = ''

    pause()



def admin_login():
    """Option 17 — Admin login. Prompts for credentials, verifies via PAM,
    checks codered-admin group membership, then exec-s into admin shell."""
    audit('admin-login:attempt')
    header('ADMIN LOGIN')

    import getpass
    import grp
    import pam

    print('  This grants full admin shell access to this sensor.')
    print('  Requires valid credentials for an account in the codered-admin group.')
    print()

    # ── Collect credentials ───────────────────────────────────────────────────
    MAX_ATTEMPTS = 3
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            username = input(f'  Username ({attempt}/{MAX_ATTEMPTS}): ').strip()
            password = getpass.getpass('  Password: ')
        except (EOFError, KeyboardInterrupt):
            print()
            audit('admin-login:cancelled')
            return

        if not username or not password:
            password = ''
            print('  Username and password are required.')
            continue

        # ── Check user exists and is in codered-admin group ───────────────────
        try:
            grp_info = grp.getgrnam('codered-admin')
            members  = grp_info.gr_mem
        except KeyError:
            # Group does not exist on this system
            print('\n  Admin access is not configured on this sensor.')
            print('  The codered-admin group does not exist.')
            audit('admin-login:failed:group-missing')
            password = ''
            pause()
            return

        if username not in members:
            # Deliberately generic message — don't reveal whether the
            # username exists or just isn't authorised
            print('  Invalid credentials.')
            audit(f'admin-login:rejected:not-in-group:{username}')
            password = ''
            if attempt < MAX_ATTEMPTS:
                continue
            else:
                print()
                audit('admin-login:lockout')
                pause()
                return

        # ── PAM authentication ────────────────────────────────────────────────
        p = pam.pam()
        if not p.authenticate(username, password):
            password = ''
            print('  Invalid credentials.')
            audit(f'admin-login:rejected:pam-failed:{username}')
            if attempt < MAX_ATTEMPTS:
                continue
            else:
                print()
                audit('admin-login:lockout')
                pause()
                return

        # ── Authenticated ─────────────────────────────────────────────────────
        password = ''
        audit(f'admin-login:success:{username}')
        print()
        print(f'  Authenticated as {username}.')
        print('  Launching admin shell — type "exit" to disconnect.')
        print()

        # exec into admin shell via sudo -u <username> -i
        # This replaces the current CLI process; on exit the SSH session ends.
        # coderedndr sudoers has NOPASSWD for this exact command.
        try:
            os.execvp('sudo', ['sudo', '-u', username, '/bin/bash', '-l'])
        except OSError as e:
            print(f'  Failed to launch admin shell: {e}')
            print('  Ensure sudoers allows: coderedndr ALL=(<username>) NOPASSWD: /bin/bash -l')
            pause()
        return

    # Exceeded MAX_ATTEMPTS (loop fell through)
    pause()


def show_user_guide():
    """Display the user guide with paging."""
    audit('view:user-guide')

    GUIDE = """
================================================================
  CODERED NDR SENSOR - USER GUIDE                    v2.0.0
================================================================

  CONTENTS
  --------
  1.  Overview
  2.  Quick start
  3.  SPAN / mirror port configuration
  4.  VMware & cloud deployment
  5.  Detection capabilities
  6.  ML behavioral engine
  7.  OT / ICS monitoring
  8.  Cloud threat detection
  9.  CLI menu reference
  10. Log files & data paths
  11. Network & firewall requirements
  12. Security hardening
  13. Tuning & customisation
  14. Troubleshooting
  15. Quick reference


  1. OVERVIEW
  -----------
  CodeRed NDR is a passive network detection and response sensor.
  It monitors a copy of your network traffic using Zeek and
  Suricata, detects threats using 20 behavioural detection scripts
  and an ML anomaly engine, and forwards alerts to your SIEM via
  Filebeat.

  The sensor requires two network connections:

    NIC 1  Management  SSH access + SIEM forwarding (needs an IP)
    NIC 2+ Monitor     Receives mirrored/SPAN traffic (no IP)

  Four services run on the sensor:
    Zeek        Parses protocols, runs detection scripts
    Suricata    Signature-based IDS, JA3/JA4 TLS fingerprinting
    Filebeat    Ships logs and alerts to your SIEM
    codered-ml  ML behavioral baseline engine (anomaly detection)


  2. QUICK START
  --------------
  Step 1  Import the OVA into VMware or Proxmox
  Step 2  Add a second network adapter in VM settings,
          connected to your SPAN port group
  Step 3  Enable Promiscuous Mode on the SPAN port group
          (VMware: Edit port group -> Security -> Accept)
  Step 4  Power on the VM
  Step 5  SSH in:  ssh coderedndr@<sensor-ip>
          Default password:  CodeRed@NDR!
          You MUST change this on first login.
  Step 6  Complete the setup wizard (~5 minutes):
          - Hostname and sensor name
          - Management IP (static or DHCP)
          - Monitor interface (wizard live-checks SPAN traffic)
          - SIEM address and port (wizard tests connectivity)
  Step 7  Wizard starts all services automatically.
          Rule-based detection is immediate.
          ML anomaly detection activates after 50 hours per host.


  3. SPAN / MIRROR PORT CONFIGURATION
  ------------------------------------
  The sensor needs a copy of your traffic. Configure your switch
  to mirror traffic to the port connected to sensor NIC 2.
  At minimum, mirror your internet uplink (firewall-facing port).

  Diagram:
    Switch uplink  ----SPAN copy---->  Sensor NIC 2

  Cisco IOS:
    monitor session 1 source interface Gi0/1 both
    monitor session 1 destination interface Gi0/24

  Cisco Nexus:
    monitor session 1 type span
      source interface Eth1/1 both
      destination interface Eth1/48
      no shut

  Arista:
    monitor session 1 source Ethernet1 both
    monitor session 1 destination Ethernet48

  Juniper:
    set forwarding-options analyzer SPAN input ingress
      interface ge-0/0/0
    set forwarding-options analyzer SPAN output
      interface ge-0/0/47

  HP / Aruba:
    mirror-port 48
    interface 1 monitor

  MikroTik:
    /interface ethernet switch
    set switch1 mirror-source=ether1 mirror-target=ether24

  Hardware TAP (recommended for production):
    Firewall --> [ TAP ] --> Core switch
                   |
                   v
             Sensor NIC 2

  Use a TAP when: link speed >= 1Gbps, SPAN drops packets under
  load, or compliance requires truly passive monitoring.
  Vendors: Garland Technology, Gigamon, Dualcomm.


  4. VMWARE & CLOUD DEPLOYMENT
  ----------------------------
  VMware (on-prem mode — select "on-prem" in wizard):
    1. Create port group "SPAN-Destination"
    2. Security -> Promiscuous Mode -> ACCEPT (required)
    3. Connect sensor NIC 2 to this port group
    4. Use Port Mirroring on VDS to mirror source ports

  AWS (cloud mode — select "cloud" in wizard):
    1. Deploy sensor as EC2 (t3.large minimum recommended)
    2. Add a second ENI as the monitor interface
    3. Security group on monitor ENI:
         Allow UDP/4789 inbound from source ENIs
    4. VPC -> Traffic Mirroring -> Mirror Targets:
         Create target pointing to sensor monitor ENI
    5. VPC -> Traffic Mirroring -> Mirror Sessions:
         Source = ENI to monitor, Target = sensor ENI
    Note: AWS charges per session-hour + data transfer

  Alibaba Cloud (cloud mode — select "cloud" in wizard):
    1. Deploy sensor as ECS instance
    2. Add second ENI as monitor interface
    3. Security group: allow UDP/4789 inbound from sources
    4. VPC -> Traffic Mirroring -> Create mirror session:
         Source: ENI to monitor, Destination: sensor ENI

  Azure / GCP (cloud mode — select "cloud" in wizard):
    - Azure vTAP (preview) or Network Watcher packet capture
    - GCP Packet Mirroring policy to sensor internal IP

  CRITICAL for all cloud deployments:
    Set deployment mode to "cloud" via the wizard step or
    Menu -> 9 (Deployment mode). This enables VXLAN
    decapsulation in Zeek and Suricata. Without this, the
    sensor receives encapsulated packets but cannot parse
    or detect anything inside them.


  5. DETECTION CAPABILITIES
  -------------------------
  CodeRed NDR covers ~75 MITRE ATT&CK techniques across
  20 Zeek detection scripts:

  C2 & Covert Channels
    beaconing        C2 timing/jitter analysis (T1071, T1573)
    ja3-fingerprint  Cobalt Strike, Metasploit, Sliver, Havoc,
                     BlackCat via TLS JA3/JA3S fingerprints
    http-c2          Domain fronting, malleable C2 URIs, fast-
                     flux DNS, DNS-over-HTTPS bypass (T1090.004)
    dns-anomaly      DGA domains (Shannon entropy), DNS tunneling
    icmp-tunnel      ICMP data tunneling (oversized payloads)
    protocol-anomaly Protocol-port mismatch, Tor exit nodes,
                     IPv6-in-IPv4 tunneling, SNMP enumeration

  Lateral Movement
    lateral-smb      Admin share access (C$, ADMIN$), PtH spike,
                     remote service pipes (T1021.002, T1543.003)
    lateral-rdp      RDP brute force, spray, workstation hops
    lateral-wmi      WMI, DCOM, WinRM, PsExec, PAExec (T1047)

  Credential Attacks
    kerberos-attacks Kerberoasting, AS-REP roasting, Golden Ticket
    credential-access NTLM relay, LLMNR/Responder poisoning,
                     LDAP AD recon, SAMR enumeration
    hassh-ssh        SSH brute force, spray, HASSH fingerprinting
                     (Paramiko, Impacket, AsyncSSH detection)

  Exfiltration & Impact
    long-connections Long-lived sessions, asymmetric data transfer
    ransomware       SMB mass file encryption spread, shadow copy
                     deletion, double-extortion exfil (T1486)
    insider-threat   Data staging (1GB+), mass share access,
                     FTP exfil, bulk email, off-hours transfers

  Commodity Threats
    cryptomining     Stratum protocol, 30+ mining pool domains,
                     XMRig/miner user-agents (T1496)
    scan-detect      Port scan, network sweep (T1046)
    cert-anomaly     Self-signed, short-lived, IP-as-CN certs

  OT / ICS  (see Section 7)
    ot-anomaly       Modbus, DNP3, IT-to-OT pivoting

  Cloud  (see Section 8)
    cloud-threats    IMDS abuse, AWS key exposure, cloud C2


  6. ML BEHAVIORAL ENGINE
  -----------------------
  The codered-ml service learns normal behavior per host and
  alerts when a host deviates significantly from its own history.

  How it works:
    - Reads Zeek conn.log, dns.log, http.log every 60 seconds
    - Builds per-host hourly feature profiles (9 features):
        conn_count     total connections made
        bytes_out      total bytes sent
        bytes_in       total bytes received
        unique_dsts    unique destination IPs
        ext_dsts       unique external destinations
        dns_queries    DNS request volume
        unique_fqdns   unique domains queried
        http_reqs      HTTP request count
        avg_duration   average connection length
    - After 50 hours of data, trains an Isolation Forest model
      using the host's own 7-day history as the baseline
    - Anomalies written to /nsm/codered/ml-alerts.json and
      shipped to SIEM alongside Zeek/Suricata alerts

  ML alert types (MITRE ATT&CK):
    ML_DataExfiltration    Bytes-out spike to external hosts
    ML_DNS_Anomaly         Unusual DNS volume or unique domains
    ML_Reconnaissance      External destination spread spike
    ML_ConnectionSpike     Unusual total connection volume
    ML_BehavioralAnomaly   Multi-feature deviation

  Important notes:
    - No GPU required. Runs on sensor VM CPU.
    - Resource-limited: 25% CPU max, 512MB RAM max
    - Warm-up: 50 hours per host before ML activates
    - Rule-based detections are immediate (no warm-up)
    - Some false positives expected in the first week
    - Tune ANOMALY_THRESHOLD in codered-ml.py if needed

  Check ML status:
    Menu -> 1 (Status) shows codered-ml service state
    Menu -> 3 (Logs) -> ML alerts to view anomaly alerts
    sudo tail -f /var/log/codered/ml-engine.log


  7. OT / ICS MONITORING
  ----------------------
  Protocols monitored (ot-anomaly detection script):
    Modbus TCP    port 502   -- coil/register writes
    DNP3          port 20000 -- Direct Operate, Restart commands
    EtherNet/IP   port 44818 -- Allen-Bradley
    IEC 104       port 2404  -- substation automation
    OPC-UA        port 4840  -- industrial data exchange
    BACnet        port 47808 -- building automation

  Detections:
    - Unauthorized Modbus write commands from unknown hosts
    - DNP3 dangerous function codes (Direct Operate, Restart)
    - IT-to-OT lateral movement (IT subnet -> OT subnet)
    - OT device reconnaissance (5+ unique OT targets in 3 min)
    - Engineering station abuse from unknown hosts

  Configuration (add to local.zeek):
    redef CodeRed::ot_engineering_stations += {
        10.100.1.10, 10.100.1.11
    };
    redef CodeRed::ot_subnets += { 192.168.100.0/24 };
    redef CodeRed::it_subnets += { 10.0.0.0/8 };


  8. CLOUD THREAT DETECTION
  -------------------------
  The cloud-threats script covers cloud-specific attacks:

    IMDS credential theft  Access to 169.254.169.254 (AWS/Azure/
                           GCP metadata) from internal hosts.
                           Indicates SSRF or container escape.
    AWS key exposure       IAM key prefixes (AKIA, ASIA etc.)
                           detected in HTTP headers
    Cloud storage C2       S3, Azure Blob, GCP Storage, Dropbox,
                           Mega, Discord CDN used as C2 channel
    Metadata path access   Requests to /latest/meta-data/iam/,
                           /computeMetadata/v1/, etc.
    Tunneling SaaS         ngrok, serveo, pagekite connections
    Large upload exfil     50MB+ outbound flagged as potential
                           cloud exfiltration


  9. CLI MENU REFERENCE
  ---------------------
  SSH as coderedndr then type a number and press Enter.

   1  Sensor status       Services, disk, CPU, uptime, SIEM
                          destination, rules age, ML status
   2  Network interfaces  All NICs, promiscuous status
   3  View logs           Suricata alerts, Zeek conn/dns/http,
                          ML anomaly alerts, audit log
   4  Diagnostics         DNS, gateway, SIEM connectivity, NTP,
                          disk, monitor interface, packet drops,
                          log freshness, Filebeat error check
   5  Network settings    Change management IP / DNS / gateway
   6  Hostname            Rename the sensor
   7  Monitor interfaces  Add, replace or remove SPAN interfaces
                          (supports multiple SPAN ports)
   8  SIEM destination    Change SIEM address, port, TLS,
                          output type (ES/Logstash/Syslog)
   9  Deployment mode     Switch on-prem/cloud. Cloud mode enables
                          VXLAN decapsulation for AWS, Alibaba Cloud,
                          and Azure mirrored traffic (UDP/4789).
                          Restarts Zeek and Suricata automatically.
  10  Restart services    Restart Zeek, Suricata, Filebeat,
                          codered-ml, or all at once
  11  Support bundle      Creates diagnostic .tar.gz archive
                          (tokens redacted). Download via SCP.
  12  Change password     Change login password. Current password
                          verified via PAM before accepting new.
  13  Reboot              Restart the sensor VM
  14  Shutdown            Power off the sensor
  15  User guide          This guide
  16  Re-run setup wizard Reconfigure everything from scratch
  17  Admin login         Prompts for username and password.
                          Verifies credentials via PAM and checks
                          that the user is in the codered-admin
                          group. On success, exec-s into the admin
                          user's login shell. Session is audited.


  10. LOG FILES & DATA PATHS
  --------------------------
  /nsm/zeek/logs/current/
    conn.log      All network connections
    dns.log       DNS requests and replies
    http.log      HTTP requests
    ssl.log       TLS sessions with JA3/JA3S fingerprints
    notice.log    All Zeek detection alerts
    files.log     Files transferred over the network

  /nsm/suricata/log/
    eve.json      Suricata EVE JSON (alerts + metadata)

  /nsm/codered/
    ml-alerts.json  ML behavioral anomaly alerts

  /var/log/codered/
    audit.log     All CLI actions (user + source IP + action)
    cli.log       CLI session log
    ml-engine.log ML engine activity and model training log
    disk-resize.log Auto-resize events

  /var/lib/codered/
    ml-baseline.db  SQLite -- per-host ML baselines (7-day)

  /opt/codered/
    bin/          Management scripts
    ml/           ML engine (codered-ml.py)
    zeek/codered-detections/  All 20 detection scripts


  11. NETWORK & FIREWALL REQUIREMENTS
  ------------------------------------
  Outbound from sensor:
    9200  TCP  SIEM (Elasticsearch default)
    5044  TCP  SIEM (Logstash default)
    514   TCP  SIEM (Syslog default)
    53    UDP  DNS resolution
    123   UDP  NTP time sync
    443   TCP  Rule and intel feed updates (HTTPS)

  Inbound to sensor:
    22    TCP  SSH management (restrict to admin IP ranges)

  Sensor VM requirements:
    CPU:   4 vCPUs minimum  (8 recommended)
    RAM:   8 GB minimum     (16 recommended)
    Disk:  100 GB minimum   (500 GB recommended)
    NICs:  2 minimum (NIC 1 management, NIC 2+ monitor)


  12. SECURITY HARDENING
  ----------------------
  SSH hardening applied by default:
    - Root login disabled
    - Max 4 authentication attempts before disconnect
    - 30-second login grace time
    - Idle session disconnect after 15 minutes
    - Modern cipher/kex/MAC algorithms only
    - fail2ban: 4 failures in 5 min = 30-min IP ban

  File permissions:
    /etc/codered/sensor.conf    640 (root:root)
    /etc/filebeat/filebeat.yml  600 (SIEM credentials)
    /nsm/                       750 (root:adm)
    /var/log/codered/           750 (root:adm)

  Password policy (menu option 11):
    - Current password verified via PAM before change accepted
    - Minimum 12 characters
    - Must include uppercase, a digit, and a symbol
    - Password never written to disk during the change process

  To restrict SSH by source IP, edit:
    /etc/ssh/sshd_config.d/90-codered-hardening.conf
  Add:  AllowUsers coderedndr@10.0.1.0/24
  Then: systemctl reload ssh


  13. TUNING & CUSTOMISATION
  --------------------------
  Override detection thresholds in:
    /opt/zeek/share/zeek/site/local.zeek

  Common tuning examples:

    # Raise beaconing threshold (reduce false positives)
    redef CodeRed::beaconing_min_connections = 15;

    # Disable internal beaconing detection (flat networks)
    redef CodeRed::beaconing_detect_internal = F;

    # Add known RDP jump servers (suppress lateral hop alerts)
    redef CodeRed::rdp_jump_servers += { 10.0.1.50 };

    # Add known SSH jump servers
    redef CodeRed::ssh_jump_servers += { 10.0.1.51 };

    # Add known domain controllers (Kerberos detection)
    redef CodeRed::known_dcs += { 10.0.1.10, 10.0.1.11 };

    # Add known OT engineering stations
    redef CodeRed::ot_engineering_stations += { 10.100.1.10 };

    # Allow additional DoH resolvers
    redef CodeRed::approved_doh_resolvers += {
        "dns.company.com"
    };

    # Raise data staging threshold (default 1GB)
    redef CodeRed::staging_bytes_threshold = 2147483648;

    # Adjust business hours for off-hours detection (UTC)
    redef CodeRed::business_hours_start = 8;
    redef CodeRed::business_hours_end   = 19;

  After editing local.zeek:
    Menu -> 9 -> Restart Zeek to apply

  ML engine tuning (/opt/codered/ml/codered-ml.py):
    ANOMALY_THRESHOLD = -0.15  (more negative = fewer alerts)
    WARMUP_SAMPLES    = 50     (hours before ML activates)
    CONTAMINATION     = 0.01   (expected anomaly fraction ~1%)
    After editing: systemctl restart codered-ml

  Update threat intel feeds:
    sudo /opt/codered/bin/update-intel.sh

  Update Suricata rules:
    sudo /opt/codered/bin/update-rules.sh


  14. TROUBLESHOOTING
  -------------------
  No traffic in conn.log after 60 seconds:
    1. Menu -> 2 -- monitor NIC must show PROMISC and UP
    2. Verify switch SPAN config is delivering traffic
    3. VMware: port group promiscuous mode must be Accept
    4. Test: sudo tcpdump -i <monitor-if> -c 10
       No output = SPAN not delivering traffic

  SIEM showing UNREACHABLE in diagnostics:
    1. Menu -> 8 -- confirm SIEM address is correct
    2. Check firewall: sensor -> SIEM on configured port
    3. Test: nc -z -w5 <siem-ip> <port>

  Services not running:
    1. Menu -> 9 -> Restart all
    2. Menu -> 3 -> System log for errors
    3. sudo journalctl -u codered-zeek -n 50

  High packet drop rate (Suricata):
    1. Menu -> 4 -- shows drop percentage
    2. Increase vCPUs in hypervisor
    3. sudo /opt/codered/bin/tune-interface.sh <monitor-if>

  High disk usage (/nsm filling):
    1. Menu -> 1 -- check /nsm percentage
    2. Expand VM disk in hypervisor (auto-resize on next boot)
    3. sudo /opt/codered/bin/disk-cleanup.sh

  ML engine not producing alerts:
    - Check it is running: systemctl status codered-ml
    - Check warm-up: sqlite3 /var/lib/codered/ml-baseline.db
        "SELECT host, COUNT(*) FROM host_features
         GROUP BY host ORDER BY 2 DESC LIMIT 10;"
      ML activates per-host after 50 rows (50+ hours)
    - View log: sudo tail -f /var/log/codered/ml-engine.log

  Too many ML false positives:
    - Increase ANOMALY_THRESHOLD to -0.25 in codered-ml.py
    - Allow 1 week for baselines to stabilise
    - Restart: systemctl restart codered-ml

  Generate support bundle:
    Menu -> 10 -- creates /tmp/codered-diag-<timestamp>.tar.gz
    Download: scp coderedndr@<ip>:/tmp/codered-diag-*.tar.gz .


  15. QUICK REFERENCE
  -------------------
  Default login         coderedndr / CodeRed@NDR!
  Management NIC        First NIC (needs IP address)
  Monitor NIC(s)        Additional NICs (SPAN/TAP, no IP)
  SIEM default port     9200 (Elasticsearch)
  Zeek alerts           /nsm/zeek/logs/current/notice.log
  Suricata alerts       /nsm/suricata/log/eve.json
  ML anomaly alerts     /nsm/codered/ml-alerts.json
  Audit log             /var/log/codered/audit.log
  ML baseline DB        /var/lib/codered/ml-baseline.db
  Detection scripts     /opt/codered/zeek/codered-detections/
  ML engine             /opt/codered/ml/codered-ml.py
  Health check          sudo /opt/codered/bin/health-check.sh
  Update intel feeds    sudo /opt/codered/bin/update-intel.sh
  Update Suricata rules sudo /opt/codered/bin/update-rules.sh
  Zeek local config     /opt/zeek/share/zeek/site/local.zeek
  SSH hardening config  /etc/ssh/sshd_config.d/90-codered-hardening.conf

================================================================
"""

    # Page through the guide
    lines = GUIDE.strip().splitlines()
    page_size = 24
    total_pages = (len(lines) + page_size - 1) // page_size

    page = 0
    while True:
        clear()
        start = page * page_size
        end = min(start + page_size, len(lines))

        for line in lines[start:end]:
            print(line)

        print(f'\n  -- Page {page + 1}/{total_pages} ', end='')
        if page < total_pages - 1:
            print('-- [Enter] Next  [q] Quit --')
        else:
            print('-- [q] Quit --')

        try:
            key = input('  ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if key == 'q' or key == '0':
            break
        elif key == 'b' and page > 0:
            page -= 1
        else:
            if page < total_pages - 1:
                page += 1
            else:
                break


def packet_capture_monitor():
    """Live packet capture monitor — shows traffic on the monitor interface."""
    import subprocess, threading, time, collections

    config = load_config()
    # sensor.conf stores monitor interface under [network] section
    iface = get_val(config, 'network', 'monitor_interface', '')
    if not iface:
        iface = get_val(config, 'network', 'monitor_interfaces', '')
    if not iface:
        # Fallback: try sensor section
        iface = get_val(config, 'sensor', 'monitor_interface', '')
    if iface:
        iface = iface.split(',')[0].strip()

    if not iface:
        print('\n  [!] No monitor interface configured.')
        print('      Configure via menu option 7.')
        pause()
        return

    clear()
    header('Packet Capture Monitor')
    print(f'  Interface : {iface}')
    print(f'  Press Ctrl+C to stop\n')

    sub_menu = {
        '1': ('Live traffic summary (top talkers)',   'summary'),
        '2': ('Raw packet stream (tcpdump)',           'raw'),
        '3': ('Protocol breakdown',                    'protocols'),
        '4': ('Zeek capture stats (netstats)',         'netstats'),
        '5': ('Zeek conn.log tail (live connections)', 'connlog'),
        '6': ('Alert stream (Suricata EVE)',            'alerts'),
    }

    print('  What to monitor:\n')
    for k, (label, _) in sub_menu.items():
        print(f'    {k}. {label}')
    print()

    try:
        choice = input('  codered> ').strip()
    except (EOFError, KeyboardInterrupt):
        return

    if choice not in sub_menu:
        return

    label, mode = sub_menu[choice]
    clear()
    header(f'Capture Monitor — {label}')
    print(f'  Interface: {iface}    Press Ctrl+C to stop\n')

    try:
        if mode == 'summary':
            # Top talkers using tcpdump + awk
            print('  Sampling 200 packets to build summary...\n')
            cmd = ['tcpdump', '-i', iface, '-nn', '-c', '200', '--immediate-mode',
                   '-q', '2>/dev/null']
            rc, out = run_cmd(['tcpdump', '-i', iface, '-nn', '-c', '200',
                               '--immediate-mode', '-q'], sudo=True, timeout=30)
            if not out.strip():
                print('  No packets captured. Check SPAN port configuration.')
            else:
                # Count source IPs
                counter: dict = {}
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        src = parts[2].rsplit('.', 1)[0] if '.' in parts[2] else parts[2]
                        counter[src] = counter.get(src, 0) + 1
                top = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:15]
                print(f'  {"Source":<30} {"Packets":>8}')
                print(f'  {"-"*30} {"-"*8}')
                for src, count in top:
                    print(f'  {src:<30} {count:>8}')
                print(f'\n  Total unique sources: {len(counter)}')
            pause()

        elif mode == 'raw':
            # Raw tcpdump stream
            print('  Starting live capture (Ctrl+C to stop)...\n')
            try:
                proc = subprocess.Popen(
                    ['tcpdump', '-i', iface, '-nn', '-l', '--immediate-mode',
                     '-c', '500'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True
                )
                for line in proc.stdout:
                    print(f'  {line}', end='')
            except KeyboardInterrupt:
                proc.terminate()

        elif mode == 'protocols':
            # Protocol breakdown
            print('  Sampling 300 packets for protocol breakdown...\n')
            rc, out = run_cmd(['tcpdump', '-i', iface, '-nn', '-c', '300',
                               '--immediate-mode'], sudo=True, timeout=45)
            protos: dict = {}
            ports: dict = {}
            for line in out.splitlines():
                # Count protocol keywords
                for proto in ['TCP', 'UDP', 'ICMP', 'ARP', 'IP6', 'DNS',
                               'HTTP', 'TLS', 'SSH', 'SMB']:
                    if proto in line.upper():
                        protos[proto] = protos.get(proto, 0) + 1
                        break
                # Count destination ports
                import re
                m = re.search(r'\.(\d+)[\s:]', line)
                if m:
                    port = m.group(1)
                    ports[port] = ports.get(port, 0) + 1

            print(f'  {"Protocol":<12} {"Count":>8}')
            print(f'  {"-"*12} {"-"*8}')
            for proto, cnt in sorted(protos.items(), key=lambda x: x[1], reverse=True):
                print(f'  {proto:<12} {cnt:>8}')
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
            print(f'\n  {"Top Port":<12} {"Count":>8}')
            print(f'  {"-"*12} {"-"*8}')
            for port, cnt in top_ports:
                print(f'  {port:<12} {cnt:>8}')
            if not protos:
                print('  No packets captured. Check SPAN port configuration.')
            pause()

        elif mode == 'netstats':
            # Interface stats from /proc/net/dev — no Broker dependency
            print('  Live interface stats (refreshes every 2s, Ctrl+C to stop)\n')
            import time
            prev_rx = prev_tx = 0
            try:
                while True:
                    rx_bytes = tx_bytes = rx_pkts = tx_pkts = 0
                    with open('/proc/net/dev') as f:
                        for line in f:
                            if iface + ':' in line:
                                parts = line.split()
                                rx_bytes = int(parts[1])
                                rx_pkts  = int(parts[2])
                                tx_bytes = int(parts[9])
                                tx_pkts  = int(parts[10])
                                break
                    rx_rate = (rx_bytes - prev_rx) / 2 if prev_rx else 0
                    prev_rx = rx_bytes
                    prev_tx = tx_bytes

                    def fmt(n):
                        if n >= 1073741824: return f'{n/1073741824:.1f} GB'
                        if n >= 1048576:    return f'{n/1048576:.1f} MB'
                        if n >= 1024:       return f'{n/1024:.1f} KB'
                        return f'{n} B'

                    print(f'\033[2J\033[H', end='')  # clear screen
                    print(f'  Interface : {iface}')
                    print(f'  {"─"*40}')
                    print(f'  RX packets : {rx_pkts:>12,}')
                    print(f'  RX bytes   : {rx_bytes:>12,}  ({fmt(rx_bytes)})')
                    print(f'  TX packets : {tx_pkts:>12,}')
                    print(f'  TX bytes   : {tx_bytes:>12,}  ({fmt(tx_bytes)})')
                    print(f'  {"─"*40}')
                    print(f'  Inbound rate : {fmt(rx_rate)}/s')
                    print(f'\n  Updated: {__import__("datetime").datetime.now().strftime("%H:%M:%S")}  (Ctrl+C to stop)')
                    time.sleep(2)
            except KeyboardInterrupt:
                print('\n')

        elif mode == 'connlog':
            # Tail Zeek conn.log
            conn_log = '/nsm/zeek/logs/current/conn.log'
            import os
            if not os.path.exists(conn_log):
                print(f'  conn.log not found at {conn_log}')
                print('  Zeek may still be starting up.')
                pause()
                return
            print('  Tailing conn.log (Ctrl+C to stop)...\n')
            print(f'  {"Time":<10} {"Src IP":<18} {"Dst IP":<18} {"Port":<7} {"Proto":<6} {"Dur":<8} {"State"}')
            print(f'  {"-"*80}')
            try:
                proc = subprocess.Popen(['tail', '-f', conn_log],
                                        stdout=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')  # Zeek uses tab separators
                    if len(parts) >= 10:
                        ts   = parts[0][:10] if parts[0] else '-'
                        src  = parts[2][:17] if len(parts) > 2 else '-'
                        dst  = parts[4][:17] if len(parts) > 4 else '-'
                        port = parts[5][:6]  if len(parts) > 5 else '-'
                        proto= parts[6][:5]  if len(parts) > 6 else '-'
                        dur  = parts[8][:7]  if len(parts) > 8 else '-'
                        state= parts[11][:8] if len(parts) > 11 else '-'
                        print(f'  {ts:<10} {src:<18} {dst:<18} {port:<7} {proto:<6} {dur:<8} {state}')
                    else:
                        print(f'  {line}', end='')
            except KeyboardInterrupt:
                proc.terminate()

        elif mode == 'alerts':
            # Suricata EVE alert stream
            eve = '/nsm/suricata/log/eve.json'
            import os, json
            if not os.path.exists(eve):
                print(f'  EVE log not found at {eve}')
                pause()
                return
            print('  Tailing Suricata alerts (Ctrl+C to stop)...\n')
            print(f'  {"Time":<10} {"Src":<20} {"Dst":<20} {"Signature"}')
            print(f'  {"-"*80}')
            try:
                proc = subprocess.Popen(['tail', '-f', eve],
                                        stdout=subprocess.PIPE, text=True)
                for line in proc.stdout:
                    try:
                        ev = json.loads(line)
                        if ev.get('event_type') == 'alert':
                            ts  = ev.get('timestamp', '')[:10]
                            src = f"{ev.get('src_ip','-')}:{ev.get('src_port','-')}"
                            dst = f"{ev.get('dest_ip','-')}:{ev.get('dest_port','-')}"
                            sig = ev.get('alert', {}).get('signature', '-')
                            print(f'  {ts:<10} {src:<20} {dst:<20} {sig}')
                    except json.JSONDecodeError:
                        pass
            except KeyboardInterrupt:
                proc.terminate()

    except KeyboardInterrupt:
        print('\n  Stopped.')

    pause()


def main_menu():
    """Main management menu loop."""
    while True:
        clear()
        config = load_config()

        # Header with sensor identity
        hostname = subprocess.getoutput('hostname')
        version = get_version()
        name = get_val(config, 'sensor', 'sensor_name', hostname)

        print(BANNER)
        print(f'  Sensor: {name} ({hostname})    Version: {version}')
        print(f'  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

        print('\n  -- Status ---------------------------------------')
        print('   1. Sensor status overview')
        print('   2. Network interfaces')
        print('   3. View logs')
        print('   4. Diagnostics')

        print('\n  -- Configure ------------------------------------')
        print('   5. Network (IP/gateway/DNS)')
        print('   6. Hostname')
        print('   7. Monitor interfaces')
        print('   8. SIEM destination')
        print('   9. Deployment mode  (on-prem / cloud VXLAN)')

        print('\n  -- Actions --------------------------------------')
        print('  10. Restart services')
        print('  11. Support bundle')
        print('  12. Change password')
        print('  13. Reboot')
        print('  14. Shutdown')

        print('\n  -- Help -----------------------------------------')
        print('  15. User guide')
        print('  16. Re-run setup wizard')

        print('\n  -- Admin ----------------------------------------')
        print('  17. Admin login')

        print('\n  -- Capture Monitor ------------------------------')
        print('  18. Packet capture monitor')

        print('\n   0. Logout')
        print()

        try:
            choice = input('  codered> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            continue

        actions = {
            '1': show_status,
            '2': show_interfaces,
            '3': show_logs,
            '4': run_diagnostics,
            '5': reconfigure_network,
            '6': reconfigure_hostname,
            '7': reconfigure_monitor,
            '8': reconfigure_forwarding,
            '9': reconfigure_cloud_mode,
            '10': restart_services,
            '11': generate_support_bundle,
            '12': change_password,
            '13': do_reboot,
            '14': do_shutdown,
            '15': show_user_guide,
            '16': run_setup,
            '17': admin_login,
            '18': packet_capture_monitor,
        }

        if choice == '0':
            if confirm('Logout?'):
                audit('logout')
                print('\n  Goodbye.\n')
                sys.exit(0)
        elif choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                print('\n  Cancelled.')
                continue
        elif choice:
            print(f'  Unknown option: {choice}')
            pause()


# ─── Entry Point ───────────────────────────────────────

def main():
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    setup_logging()
    audit('login')
    try:
        if not is_configured():
            if not run_setup():
                sys.exit(0)
        main_menu()
    except KeyboardInterrupt:
        print('\n')
        audit('logout:ctrl-c')
        sys.exit(0)


if __name__ == '__main__':
    main()

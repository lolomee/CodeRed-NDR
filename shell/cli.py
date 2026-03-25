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
    """Apply management network configuration."""
    iface = get_val(config, 'network', 'mgmt_interface', 'ens32')
    mode = get_val(config, 'network', 'mgmt_mode', 'dhcp')
    conn_name = f'codered-{iface}'

    audit(f'apply-network:{iface}:{mode}')

    # Delete existing connection
    run_cmd(['nmcli', 'connection', 'delete', conn_name], sudo=True)

    if mode == 'dhcp':
        rc, out = run_cmd(['nmcli', 'connection', 'add',
            'con-name', conn_name, 'ifname', iface, 'type', 'ethernet',
            'ipv4.method', 'auto', 'connection.autoconnect', 'yes'], sudo=True)
    else:
        ip = get_val(config, 'network', 'mgmt_ip')
        mask = get_val(config, 'network', 'mgmt_netmask', '255.255.255.0')
        gw = get_val(config, 'network', 'mgmt_gateway')
        dns = get_val(config, 'network', 'mgmt_dns', '8.8.8.8')
        cidr = netmask_to_cidr(mask)
        dns_str = ' '.join(s.strip() for s in dns.split(','))

        rc, out = run_cmd(['nmcli', 'connection', 'add',
            'con-name', conn_name, 'ifname', iface, 'type', 'ethernet',
            'ipv4.method', 'manual',
            'ipv4.addresses', f'{ip}/{cidr}',
            'ipv4.gateway', gw,
            'ipv4.dns', dns_str,
            'connection.autoconnect', 'yes'], sudo=True)

    if rc != 0:
        print(f'    ! Network config failed: {out}')
        return False

    run_cmd(['nmcli', 'connection', 'up', conn_name], timeout=15, sudo=True)
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
    """Update Zeek node.cfg with monitor interface(s)."""
    mon_ifaces = get_monitor_interfaces(config)
    if not mon_ifaces:
        return

    # For standalone mode, use first interface
    # TODO: cluster mode for multiple interfaces
    iface = mon_ifaces[0]
    node_cfg = '/opt/zeek/etc/node.cfg'

    content = f"""# CodeRed NDR - Zeek Node Configuration
# Auto-generated by CLI — do not edit manually

[zeek]
type=standalone
host=localhost
interface=af_packet::{iface}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as f:
        f.write(content)
        tmp = f.name
    run_cmd(['cp', tmp, node_cfg], sudo=True)
    run_cmd(['chmod', '644', node_cfg], sudo=True)
    os.unlink(tmp)

    # Tune each monitor interface
    for mon in mon_ifaces:
        run_cmd(['/opt/codered/bin/tune-interface.sh', mon], sudo=True)


def apply_suricata_config(config: configparser.ConfigParser):
    """Update Suricata config with monitor interface."""
    mon_ifaces = get_monitor_interfaces(config)
    if not mon_ifaces:
        return

    iface = mon_ifaces[0]
    override = '/etc/suricata/codered-override.yaml'
    community_id = get_val(config, 'suricata', 'community_id', 'yes')

    content = f"""%YAML 1.1
---
# CodeRed NDR - Suricata Override Configuration
# Auto-generated by CLI — do not edit manually

af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

community-id:
  enabled: {'true' if community_id == 'yes' else 'false'}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /nsm/suricata/log/eve.json
      community-id: {'true' if community_id == 'yes' else 'false'}
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
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(content)
        tmp = f.name
    run_cmd(['mkdir', '-p', '/etc/suricata'], sudo=True)
    run_cmd(['cp', tmp, override], sudo=True)
    run_cmd(['chmod', '644', override], sudo=True)
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
    if siem_output == 'logstash':
        content += f"""output.logstash:
  enabled: true
  hosts: ["{endpoint}:{port}"]
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

    # ── Monitor Interfaces ──
    header('3. MONITORING INTERFACES (SPAN/MIRROR PORTS)')
    print('  Select the interfaces connected to your SPAN/mirror ports.')
    print('  You can select multiple interfaces for multi-zone monitoring.\n')
    mon_ifaces = prompt_multi_interface('Monitor interface(s)', exclude=[mgmt_iface])
    config.set('network', 'monitor_interfaces', ','.join(mon_ifaces))
    config.set('network', 'monitor_interface', mon_ifaces[0])

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

    # ── Optional Features ──
    header('6. OPTIONAL FEATURES')
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
    print_line('Monitor Interfaces:', ', '.join(mon_ifaces))
    print_line('Sensor Name:', name)
    print_line('SIEM Destination:', f'{endpoint}:{get_val(config, "forwarding", "siem_port", "9200")}' if endpoint else 'not configured')
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

    print(f'  [4/5] Configuring {len(mon_ifaces)} monitor interface(s)...')
    apply_monitor_interfaces(mon_ifaces)

    print('  [5/5] Starting sensor services...')
    # Configure Zeek node.cfg with monitor interfaces
    apply_zeek_config(config)
    # Configure Suricata
    apply_suricata_config(config)
    # Configure Filebeat
    apply_filebeat_config(config)
    # Enable and start services
    for svc in ['codered-zeek', 'codered-suricata', 'filebeat']:
        run_cmd(['systemctl', 'enable', svc], sudo=True)
        run_cmd(['systemctl', 'start', svc], sudo=True)
    # Update Suricata rules
    run_cmd(['/opt/codered/bin/update-rules.sh'], timeout=120, sudo=True)

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
    for display_name, svc in [('Zeek', 'codered-zeek'), ('Suricata', 'codered-suricata'), ('Filebeat', 'filebeat')]:
        rc, out = run_cmd(['systemctl', 'is-active', svc], sudo=True)
        status = out.strip()
        if status == 'active':
            print_line(f'    {display_name}:', 'RUNNING', 20)
        else:
            print_line(f'    {display_name}:', status, 20)

    # Monitor interfaces
    print()
    mon_ifaces = get_monitor_interfaces(config)
    if mon_ifaces:
        print_line('Monitor Interfaces:', ', '.join(mon_ifaces))
    else:
        print_line('Monitor Interfaces:', 'none configured')

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
        '1': ('All NDR services', ['codered-zeek', 'codered-suricata', 'filebeat']),
        '2': ('Zeek', ['codered-zeek']),
        '3': ('Suricata', ['codered-suricata']),
        '4': ('Filebeat', ['filebeat']),
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
    print('  Current settings:')
    print_line('SIEM Address:', current_host or 'not configured')
    print_line('SIEM Port:', current_port)
    print()

    endpoint = prompt('SIEM address (IP or FQDN)', current_host, is_valid_host, required=False)
    config.set('forwarding', 'siem_host', endpoint)

    if endpoint:
        port = prompt('SIEM port', current_port, is_valid_port)
        config.set('forwarding', 'siem_port', port)

    if confirm('Apply forwarding changes?'):
        save_config(config)
        print('\n  Applying forwarding configuration...')
        apply_filebeat_config(config)
        run_cmd(['systemctl', 'restart', 'filebeat'], sudo=True)
        print('  Done.')
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

    # SIEM connectivity
    endpoint = get_val(config, 'forwarding', 'siem_host')
    if not endpoint:
        endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint:
        rc, _ = run_cmd(['bash', '-c', f'echo | timeout 5 openssl s_client -connect {endpoint}:{port} 2>/dev/null'])
        if rc != 0:
            rc, _ = run_cmd(['bash', '-c', f'echo > /dev/tcp/{endpoint}/{port}'], timeout=5)
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
    try:
        current = getpass.getpass('  Current password: ')
        new_pw = getpass.getpass('  New password: ')
        confirm_pw = getpass.getpass('  Confirm new password: ')
    except EOFError:
        return

    if new_pw != confirm_pw:
        print('\n  Passwords do not match.')
        pause()
        return

    if len(new_pw) < 8:
        print('\n  Password must be at least 8 characters.')
        pause()
        return

    # Use chpasswd via sudo with dynamic user detection
    current_user = os.environ.get('SUDO_USER', os.environ.get('USER', 'coderedndr'))
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pw', delete=False) as f:
        f.write(f'{current_user}:{new_pw}')
        tmp = f.name
    os.chmod(tmp, 0o600)
    rc, out = run_cmd(['bash', '-c', f'cat {tmp} | chpasswd && rm -f {tmp}'], sudo=True)
    try:
        os.unlink(tmp)
    except OSError:
        pass
    if rc == 0:
        print('\n  Password changed successfully.')
        audit('change-password:success')
    else:
        print(f'\n  Failed to change password: {out}')
        audit('change-password:failed')
    pause()


def show_user_guide():
    """Display the user guide with paging."""
    audit('view:user-guide')

    GUIDE = """
============================================================
  CODERED NDR SENSOR - USER GUIDE
============================================================

  OVERVIEW
  ────────
  This sensor passively monitors your network traffic for
  threats and anomalies. It needs two network connections:

    NIC 1 (first NIC) = Management (SSH access + SIEM forwarding)
    NIC 2+ (additional NICs) = Monitor (receives mirrored/SPAN traffic)


  QUICK START
  ───────────
  1. Import the OVA into your hypervisor (VMware/Proxmox)
  2. Assign two NICs:
     - NIC 1 → your management network
     - NIC 2 → your SPAN/mirror port group
  3. Power on, SSH in: ssh coderedndr@<ip>
  4. Complete the setup wizard
  5. Sensor starts monitoring automatically


  HOW TO CONFIGURE SPAN / MIRROR PORT
  ────────────────────────────────────
  The sensor needs a copy of your network traffic. Configure
  your switch to mirror traffic to the port connected to the
  sensor's monitor NIC(s).

  At minimum, mirror your INTERNET UPLINK port (the port
  connecting to your firewall/router).

  ┌──────────────┐
  │   Switch     │
  │              │   SPAN / Mirror
  │  Uplink ─────┼──────────────────▶  Sensor NIC 2
  │  (to FW)     │   (copy of traffic)
  └──────────────┘

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
    set forwarding-options analyzer SPAN input ingress interface ge-0/0/0
    set forwarding-options analyzer SPAN input egress interface ge-0/0/0
    set forwarding-options analyzer SPAN output interface ge-0/0/47

  HP / Aruba:
    mirror-port 48
    interface 1 monitor

  MikroTik:
    /interface ethernet switch
    set switch1 mirror-source=ether1 mirror-target=ether24


  VMWARE VIRTUAL ENVIRONMENT
  ──────────────────────────
  If monitoring VMs on the same ESXi host:

  1. Create a port group for SPAN (e.g., "SPAN-Destination")
  2. Set Security → Promiscuous Mode → ACCEPT
  3. Connect the sensor's NIC 2 to this port group
  4. For VDS: use Port Mirroring to mirror source ports
     to the sensor's port

  IMPORTANT: Promiscuous mode MUST be enabled on the port
  group connected to the sensor's monitor NIC(s).


  USING A NETWORK TAP (RECOMMENDED)
  ──────────────────────────────────
  A hardware TAP is more reliable than SPAN for production:

    Firewall ──▶ [ TAP ] ◀── Core Switch
                    │
                    ▼
              Sensor NIC 2

  TAP vendors: Garland Technology, Gigamon, Dualcomm

  Use a TAP when:
  - Monitoring 1 Gbps+ links
  - SPAN drops packets under load
  - Compliance requires passive monitoring


  NETWORK REQUIREMENTS
  ────────────────────
  Open these ports FROM the sensor:

    Port   │ Direction  │ Purpose
    ───────┼────────────┼──────────────
    9200   │ Outbound   │ SIEM forwarding
    53     │ Outbound   │ DNS
    123    │ Outbound   │ NTP
    22     │ Inbound    │ SSH management

  Sensor VM requirements:
    Minimum:      4 CPU,  8 GB RAM, 100 GB disk
    Recommended:  8 CPU, 16 GB RAM, 500 GB disk


  TROUBLESHOOTING
  ───────────────
  Not receiving traffic?
    1. Menu → 2 (Interfaces) → check monitor NIC shows PROMISC
    2. Verify SPAN is active on your switch
    3. VMware: check promiscuous mode on port group

  Cannot reach SIEM?
    1. Menu → 4 (Diagnostics) → check SIEM connectivity line
    2. Verify firewall allows sensor → SIEM on configured port

  High disk usage?
    1. Menu → 1 (Status) → check /nsm usage
    2. Increase VM disk in hypervisor if needed

  Services not running?
    1. Menu → 9 (Restart services) → restart all


  QUICK REFERENCE
  ───────────────
  Default login:     coderedndr / CodeRed@NDR!
  Management NIC:    First NIC (needs IP address)
  Monitor NICs:      Additional NICs (SPAN ports, no IP)
  SIEM default port: 9200

============================================================
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

        print('\n  -- Actions --------------------------------------')
        print('   9. Restart services')
        print('  10. Support bundle')
        print('  11. Change password')
        print('  12. Reboot')
        print('  13. Shutdown')

        print('\n  -- Help -----------------------------------------')
        print('  14. User guide')
        print('  15. Re-run setup wizard')

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
            '9': restart_services,
            '10': generate_support_bundle,
            '11': change_password,
            '12': do_reboot,
            '13': do_shutdown,
            '14': show_user_guide,
            '15': run_setup,
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

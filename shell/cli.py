#!/usr/bin/env python3
"""CodeRed NDR - Management CLI.

Usage: sudo coderedndr

Provides a management menu for configuring and operating the
CodeRed NDR sensor. Must be run as root (sudo).
"""

import configparser
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
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
        return int(netmask)
    if netmask.startswith('/'):
        return int(netmask[1:])
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

def run_cmd(cmd: list[str], timeout: int = 30, **kwargs) -> tuple[int, str]:
    """Run a command. Already running as root via 'sudo coderedndr'."""
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
    os.makedirs(CONF_DIR, mode=0o755, exist_ok=True)
    with open(CONF_FILE, 'w') as f:
        f.write('# CodeRed NDR Configuration\n')
        f.write(f'# Last modified: {datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}\n\n')
        config.write(f)
    os.chmod(CONF_FILE, 0o640)

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
    rc, out = run_cmd(['hostnamectl', 'set-hostname', hostname])
    return rc == 0

def apply_network(config: configparser.ConfigParser) -> bool:
    """Apply management network configuration."""
    iface = get_val(config, 'network', 'mgmt_interface', 'ens32')
    mode = get_val(config, 'network', 'mgmt_mode', 'dhcp')
    conn_name = f'codered-{iface}'

    audit(f'apply-network:{iface}:{mode}')

    # Delete existing connection
    run_cmd(['nmcli', 'connection', 'delete', conn_name])

    if mode == 'dhcp':
        rc, out = run_cmd(['nmcli', 'connection', 'add',
            'con-name', conn_name, 'ifname', iface, 'type', 'ethernet',
            'ipv4.method', 'auto', 'connection.autoconnect', 'yes'])
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
            'connection.autoconnect', 'yes'])

    if rc != 0:
        print(f'    ! Network config failed: {out}')
        return False

    run_cmd(['nmcli', 'connection', 'up', conn_name], timeout=15)
    return True

def apply_monitor_interface(iface: str) -> bool:
    """Set a single monitoring interface to promiscuous, no IP."""
    audit(f'apply-monitor:{iface}')
    run_cmd(['ip', 'link', 'set', iface, 'up', 'promisc', 'on'])
    run_cmd(['ip', 'addr', 'flush', 'dev', iface])
    for feature in ['rx', 'tx', 'sg', 'tso', 'gso', 'gro', 'lro']:
        run_cmd(['ethtool', '-K', iface, feature, 'off'])
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

    # ── Sensor Identity ──
    header('4. SENSOR IDENTITY')
    name = prompt('Sensor name', get_val(config, 'sensor', 'sensor_name', 'sensor-01'))
    config.set('sensor', 'sensor_name', name)
    token = prompt('Registration token', get_val(config, 'sensor', 'registration_token'), required=False)
    config.set('sensor', 'registration_token', token)

    # ── CodeRed AI Forwarding ──
    header('5. CODERED AI LOG FORWARDING')
    endpoint = prompt('CodeRed AI IP address', get_val(config, 'forwarding', 'siem_endpoint'), is_valid_ip, required=False)
    config.set('forwarding', 'siem_endpoint', endpoint)

    if endpoint:
        port = prompt('CodeRed AI port', get_val(config, 'forwarding', 'siem_port', '9200'), is_valid_port)
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
    print_line('CodeRed AI:', f'{endpoint}:{get_val(config, "forwarding", "siem_port", "9200")}' if endpoint else 'not configured')
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

    print('  [5/5] Applying sensor services...')
    rc, out = run_cmd(['salt-call', '--local', 'state.apply', 'codered'], timeout=600)
    if rc != 0:
        logging.error('Salt apply failed: %s', out)
        print('    ! Warning: Some services may not have started correctly.')
        print(f'    ! Check /var/log/codered/cli.log for details.')

    # Mark setup complete
    Path(SETUP_SENTINEL).touch(mode=0o644)
    audit('setup-complete')

    print('\n  ✓ Setup complete. Sensor is now active.')
    print('  ✓ You will see the management menu on next login.\n')
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
    for svc_name, check in [
        ('Zeek', lambda: run_cmd(['pgrep', '-x', 'zeek'])[0] == 0),
        ('Suricata', lambda: run_cmd(['systemctl', 'is-active', 'suricata'])[1].strip() == 'active'),
        ('Filebeat', lambda: run_cmd(['systemctl', 'is-active', 'filebeat'])[1].strip() == 'active'),
    ]:
        is_running = check()
        print_line(f'    {svc_name}:', 'RUNNING' if is_running else 'stopped', 20)

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
    endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint:
        print_line('CodeRed AI:', f'{endpoint}:{port}')
    else:
        print_line('CodeRed AI:', 'not configured')

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
        '1': ('Suricata alerts', '/nsm/suricata/eve.json'),
        '2': ('Zeek DNS', '/nsm/zeek/logs/current/dns.log'),
        '3': ('Zeek connections', '/nsm/zeek/logs/current/conn.log'),
        '4': ('Zeek HTTP', '/nsm/zeek/logs/current/http.log'),
        '5': ('System log', '/var/log/syslog'),
        '6': ('Audit log', AUDIT_LOG),
    }
    for k, (name, path) in logs.items():
        exists = '✓' if os.path.exists(path) else '✗'
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
        '1': ('Zeek', 'zeek'),
        '2': ('Suricata', 'suricata'),
        '3': ('Filebeat', 'filebeat'),
        '4': ('All NDR services', 'all'),
    }
    for k, (name, _) in services.items():
        print(f'  {k}. {name}')
    print(f'  0. Back')

    try:
        choice = input('\n  Select: ').strip()
    except EOFError:
        return

    if choice in services:
        name, svc = services[choice]
        if confirm(f'Restart {name}?'):
            audit(f'restart:{name}')
            print(f'\n  Restarting {name}...')
            if svc == 'all':
                run_cmd(['systemctl', 'restart', 'suricata'])
                run_cmd(['/opt/zeek/bin/zeekctl', 'restart'], timeout=60)
                run_cmd(['systemctl', 'restart', 'filebeat'])
            elif svc == 'zeek':
                run_cmd(['/opt/zeek/bin/zeekctl', 'restart'], timeout=60)
            else:
                run_cmd(['systemctl', 'restart', svc])
            print('  Done.')
            pause()


def reconfigure_network():
    """Reconfigure sensor IP, gateway, DNS."""
    audit('reconfigure:network')
    config = load_config()

    # Auto-detect current management interface (the one with an IP)
    current_iface = get_val(config, 'network', 'mgmt_interface')
    if not current_iface:
        # Find interface with an IP (excluding lo)
        _, out = run_cmd(['ip', '-4', '-br', 'addr', 'show'])
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] != 'lo' and '/' in parts[2]:
                current_iface = parts[0]
                break
        if not current_iface:
            current_iface = 'eth0'

    # Get current IP info
    current_ip = get_val(config, 'network', 'mgmt_ip')
    current_mask = get_val(config, 'network', 'mgmt_netmask', '255.255.255.0')
    current_gw = get_val(config, 'network', 'mgmt_gateway')
    current_dns = get_val(config, 'network', 'mgmt_dns')

    # If no config yet, detect from system
    if not current_ip:
        _, out = run_cmd(['ip', '-4', '-br', 'addr', 'show', current_iface])
        if out.strip():
            parts = out.strip().split()
            if len(parts) >= 3 and '/' in parts[2]:
                current_ip = parts[2].split('/')[0]
                cidr = parts[2].split('/')[1]
                current_mask = cidr
    if not current_gw:
        _, out = run_cmd(['ip', 'route', 'show', 'default'])
        if 'via' in out:
            current_gw = out.split('via')[1].strip().split()[0]
    if not current_dns:
        try:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        current_dns = line.split()[1]
                        break
        except OSError:
            current_dns = '8.8.8.8'

    header('NETWORK SETTINGS')
    print('  Current settings:')
    print_line('IP Address:', current_ip or 'DHCP')
    print_line('Netmask:', current_mask)
    print_line('Gateway:', current_gw or 'auto')
    print_line('DNS:', current_dns or 'auto')
    print()

    mode = prompt_choice('IP mode', ['static', 'dhcp'], 'static')
    config.set('network', 'mgmt_mode', mode)
    config.set('network', 'mgmt_interface', current_iface)

    if mode == 'static':
        ip = prompt('IP address', current_ip, is_valid_ip)
        mask = prompt('Netmask', current_mask, is_valid_netmask)
        gw = prompt('Gateway', current_gw, is_valid_ip)
        dns = prompt('DNS (comma-separated)', current_dns or '8.8.8.8')
        config.set('network', 'mgmt_ip', ip)
        config.set('network', 'mgmt_netmask', mask)
        config.set('network', 'mgmt_gateway', gw)
        config.set('network', 'mgmt_dns', dns)

    print()
    if mode == 'static':
        print(f'  New settings: {ip}/{netmask_to_cidr(mask)} gw {gw} dns {dns}')
    else:
        print('  New settings: DHCP (automatic)')

    # Check if IP is changing
    ip_changing = (mode == 'static' and ip != current_ip) or (mode == 'dhcp' and current_ip)

    if ip_changing:
        print('\n  ⚠ WARNING: The IP address is changing.')
        print('  Your SSH session will disconnect after applying.')
        if mode == 'static':
            print(f'\n  Reconnect with: ssh <your-user>@{ip}')
        else:
            print('\n  Reconnect using the DHCP-assigned IP.')
            print('  Check your DHCP server or VM console for the new IP.')

    if not confirm('\n  Apply now?'):
        return

    save_config(config)
    apply_network(config)

    if ip_changing and mode == 'static':
        print(f'\n  ✓ Network applied. Reconnect: ssh <your-user>@{ip}')
        print('  Session will disconnect in 3 seconds...')
        import time
        time.sleep(3)
    else:
        print('  ✓ Network configuration applied.')
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
    """Reconfigure CodeRed AI forwarding — just IP and port."""
    audit('reconfigure:forwarding')
    config = load_config()

    header('RECONFIGURE CODERED AI DESTINATION')
    current_ip = get_val(config, 'forwarding', 'siem_endpoint')
    current_port = get_val(config, 'forwarding', 'siem_port', '9200')
    print('  Current settings:')
    print_line('CodeRed AI IP:', current_ip or 'not configured')
    print_line('CodeRed AI Port:', current_port)
    print()

    endpoint = prompt('CodeRed AI IP address', current_ip, is_valid_ip, required=False)
    config.set('forwarding', 'siem_endpoint', endpoint)

    if endpoint:
        port = prompt('CodeRed AI port', current_port, is_valid_port)
        config.set('forwarding', 'siem_port', port)

    if confirm('Apply forwarding changes?'):
        save_config(config)
        print('\n  Applying forwarding configuration...')
        rc, _ = run_cmd(['salt-call', '--local', 'state.apply', 'codered.forwarding'], timeout=120)
        print(f'  {"Done." if rc == 0 else "Completed with warnings."}')
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
        save_config(config)
        print('\n  Applying monitor interfaces...')
        apply_monitor_interfaces(new_ifaces)
        print('  Restarting Zeek and Suricata...')
        run_cmd(['salt-call', '--local', 'state.apply', 'codered.zeek', 'codered.suricata'], timeout=300)
        print('  Done.')
        pause()

    elif choice == '2':
        print(f'\n  Current: {", ".join(current)}')
        add_ifaces = prompt_multi_interface('Interface(s) to add', exclude=[mgmt] + current)
        new_list = current + add_ifaces
        config.set('network', 'monitor_interfaces', ','.join(new_list))
        save_config(config)
        print('\n  Configuring new interfaces...')
        apply_monitor_interfaces(add_ifaces)
        print('  Restarting Zeek and Suricata...')
        run_cmd(['salt-call', '--local', 'state.apply', 'codered.zeek', 'codered.suricata'], timeout=300)
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
            save_config(config)
            print('  Restarting Zeek and Suricata...')
            run_cmd(['salt-call', '--local', 'state.apply', 'codered.zeek', 'codered.suricata'], timeout=300)
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
        rc, _ = run_cmd(['ping', '-c', '1', '-W', '3', gw])
        print_line('Gateway reachable:', 'OK' if rc == 0 else 'FAIL')

    # CodeRed AI connectivity
    endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint:
        rc, _ = run_cmd(['bash', '-c', f'echo | timeout 5 openssl s_client -connect {endpoint}:{port} 2>/dev/null'])
        if rc != 0:
            rc, _ = run_cmd(['bash', '-c', f'echo > /dev/tcp/{endpoint}/{port}'], timeout=5)
        print_line(f'CodeRed AI ({endpoint}:{port}):', 'OK' if rc == 0 else 'UNREACHABLE')

    # NTP sync
    rc, out = run_cmd(['timedatectl', 'show', '--property=NTPSynchronized'])
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
        _, link_out = run_cmd(['ip', 'link', 'show', mon])
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
    for svc, proc in [('Zeek', 'zeek'), ('Suricata', 'suricata'), ('Filebeat', 'filebeat')]:
        rc, _ = run_cmd(['pgrep', '-x', proc])
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
    docker ps -a > $TMPDIR/docker.txt 2>&1 || true
    cp /etc/codered/sensor.conf $TMPDIR/sensor.conf 2>/dev/null || true
    # Redact tokens
    sed -i 's/token = .*/token = [REDACTED]/' $TMPDIR/sensor.conf 2>/dev/null || true
    sed -i 's/siem_token = .*/siem_token = [REDACTED]/' $TMPDIR/sensor.conf 2>/dev/null || true
    tail -200 /var/log/codered/cli.log > $TMPDIR/cli.log 2>/dev/null || true
    tail -200 /var/log/codered/audit.log > $TMPDIR/audit.log 2>/dev/null || true
    tail -500 /var/log/syslog > $TMPDIR/syslog-tail.txt 2>/dev/null || true
    journalctl -u zeek -u suricata --since "1 hour ago" --no-pager > $TMPDIR/journal.txt 2>/dev/null || true
    systemctl status suricata zeek filebeat > $TMPDIR/service-status.txt 2>/dev/null || true
    /opt/zeek/bin/zeekctl status > $TMPDIR/zeek-status.txt 2>/dev/null || true
    tar czf {bundle_path} -C $(dirname $TMPDIR) $(basename $TMPDIR)
    rm -rf $TMPDIR
    """

    rc, _ = run_cmd(['bash', '-c', script], timeout=60)
    if rc == 0 and os.path.exists(bundle_path):
        size = os.path.getsize(bundle_path) // 1024
        print(f'  Bundle created: {bundle_path} ({size} KB)')
        print(f'  Download via: scp sensoradmin@<sensor-ip>:{bundle_path} .')
    else:
        print('  Failed to create bundle.')
    pause()


def do_reboot():
    """Reboot the sensor."""
    audit('reboot')
    if confirm('Reboot the sensor now?', default=False):
        print('\n  Rebooting...')
        run_cmd(['shutdown', '-r', 'now'])


def do_shutdown():
    """Shut down the sensor."""
    audit('shutdown')
    if confirm('Shut down the sensor? All monitoring will stop.', default=False):
        print('\n  Shutting down...')
        run_cmd(['shutdown', '-h', 'now'])



def get_setup_checklist(config) -> list[tuple[bool, str]]:
    """Return setup checklist with status."""
    checks = []

    # Network
    ip = get_val(config, 'network', 'mgmt_ip')
    mode = get_val(config, 'network', 'mgmt_mode')
    if ip or mode == 'dhcp':
        # Get live IP
        _, out = run_cmd(['hostname', '-I'])
        live_ip = out.strip().split()[0] if out.strip() else ''
        checks.append((True, f'Network configured ({live_ip or ip or "DHCP"})'))
    else:
        checks.append((False, 'Network not configured'))

    # Hostname
    current_hostname = subprocess.getoutput('hostname').strip()
    if current_hostname and current_hostname not in ('localhost', 'ubuntu', 'codered-sensor', 'ip-172-31-27-3'):
        checks.append((True, f'Hostname set ({current_hostname})'))
    else:
        checks.append((False, 'Hostname (still default)'))

    # Monitor interfaces
    mon = get_monitor_interfaces(config)
    if mon:
        checks.append((True, f'Monitor interfaces ({", ".join(mon)})'))
    else:
        checks.append((False, 'Monitor interfaces (none configured)'))

    # CodeRed AI
    endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')
    if endpoint:
        checks.append((True, f'CodeRed AI destination ({endpoint}:{port})'))
    else:
        checks.append((False, 'CodeRed AI destination (not configured)'))

    # NDR services
    zeek_running = run_cmd(['pgrep', '-x', 'zeek'])[0] == 0
    suri_running = run_cmd(['pgrep', '-x', 'suricata'])[0] == 0
    if zeek_running and suri_running:
        checks.append((True, 'NDR services running'))
    elif zeek_running or suri_running:
        checks.append((False, 'NDR services (partially running)'))
    else:
        checks.append((False, 'NDR services (not started)'))

    return checks


def start_ndr_services():
    """Start Zeek, Suricata, and Filebeat."""
    audit('start-ndr')
    config = load_config()

    header('START NDR SERVICES')

    # Pre-flight checks
    mon = get_monitor_interfaces(config)
    if not mon:
        print('  ✗ Cannot start: No monitor interfaces configured.')
        print('  → Use option 7 to configure monitor interfaces first.')
        pause()
        return

    print('  Pre-flight checks:')

    # Check monitor interfaces are up
    all_ok = True
    for iface in mon:
        _, out = run_cmd(['ip', 'link', 'show', iface])
        if 'UP' in out:
            print_line(f'    {iface}:', 'UP')
        else:
            print_line(f'    {iface}:', 'DOWN — bringing up...')
            apply_monitor_interface(iface)
            all_ok = True

    endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    if endpoint:
        print_line('    CodeRed AI:', f'{endpoint}:{get_val(config, "forwarding", "siem_port", "9200")}')
    else:
        print_line('    CodeRed AI:', 'not configured (logs stored locally only)')

    print()
    if not confirm('Start Zeek + Suricata + Filebeat?'):
        return

    # Configure monitor interfaces
    print('\n  Configuring monitor interfaces...')
    for iface in mon:
        apply_monitor_interface(iface)

    # Start Suricata
    print('  Starting Suricata...')
    # Configure Suricata to listen on monitor interfaces
    suricata_ifaces = ' '.join(f'-i {iface}' for iface in mon)
    rc, out = run_cmd(['systemctl', 'start', 'suricata'])
    if rc == 0:
        print_line('    Suricata:', 'started')
    else:
        print_line('    Suricata:', f'failed — {out.strip()[:80]}')

    # Start Zeek
    print('  Starting Zeek...')
    # Create basic Zeek node.cfg if it doesn't exist
    zeek_dir = '/opt/zeek'
    if os.path.isdir(zeek_dir):
        node_cfg = f'{zeek_dir}/etc/node.cfg'
        local_zeek = f'{zeek_dir}/share/zeek/site/local.zeek'

        # Write node.cfg for monitor interfaces
        try:
            with open('/tmp/node.cfg', 'w') as f:
                f.write('[zeek]\ntype=standalone\nhost=localhost\n')
                f.write(f'interface={mon[0]}\n')
            run_cmd(['cp', '/tmp/node.cfg', node_cfg])
        except OSError:
            pass

    rc, out = run_cmd([f'{zeek_dir}/bin/zeekctl', 'deploy'], timeout=60)
    if rc == 0:
        print_line('    Zeek:', 'started')
    else:
        # Try direct start
        rc2, _ = run_cmd([f'{zeek_dir}/bin/zeekctl', 'start'], timeout=60)
        print_line('    Zeek:', 'started' if rc2 == 0 else f'failed')

    # Start Filebeat if CodeRed AI is configured
    if endpoint:
        print('  Starting Filebeat...')
        rc, out = run_cmd(['systemctl', 'start', 'filebeat'])
        print_line('    Filebeat:', 'started' if rc == 0 else 'failed')

    # Enable timers
    print('  Enabling auto-update timers...')
    run_cmd(['systemctl', 'enable', '--now', 'codered-rule-update.timer'])
    run_cmd(['systemctl', 'enable', '--now', 'codered-update.timer'])

    print('\n  ✓ NDR services started.')
    print('  Use option 1 (Status) to verify, option 4 (Diagnostics) to test.')
    pause()


def stop_ndr_services():
    """Stop Zeek, Suricata, and Filebeat."""
    audit('stop-ndr')
    header('STOP NDR SERVICES')

    print('  This will stop all network monitoring.')
    if not confirm('Stop Zeek + Suricata + Filebeat?', default=False):
        return

    print('\n  Stopping services...')

    zeek_dir = '/opt/zeek'
    if os.path.isdir(f'{zeek_dir}/bin'):
        run_cmd([f'{zeek_dir}/bin/zeekctl', 'stop'], timeout=60)
    run_cmd(['systemctl', 'stop', 'suricata'])
    run_cmd(['systemctl', 'stop', 'filebeat'])

    print('  ✓ All NDR services stopped. No traffic is being monitored.')
    pause()


def test_monitor_interface():
    """Test if packets are arriving on monitor interfaces."""
    audit('test-monitor')
    config = load_config()
    mon = get_monitor_interfaces(config)

    header('TEST MONITOR INTERFACES')

    if not mon:
        print('  No monitor interfaces configured.')
        print('  → Use option 7 to configure monitor interfaces first.')
        pause()
        return

    print('  Testing packet capture on each monitor interface...')
    print('  (Listening for 5 seconds per interface)\n')

    for iface in mon:
        # Check interface is UP
        _, link_out = run_cmd(['ip', 'link', 'show', iface])
        if 'UP' not in link_out:
            print_line(f'  {iface}:', 'DOWN — skipping (bring up first)')
            continue

        print(f'  Listening on {iface}...', end=' ', flush=True)
        rc, out = run_cmd(
            ['timeout', '5', 'tcpdump', '-i', iface, '-c', '100', '-q', '--immediate-mode'],
            sudo=True, timeout=10
        )

        # Parse packet count from tcpdump output
        # tcpdump outputs "X packets captured" on stderr
        import re
        match = re.search(r'(\d+) packets? captured', out)
        if match:
            count = int(match.group(1))
            if count > 0:
                print(f'{count} packets in 5 seconds ✓')
            else:
                print('0 packets ✗ (check SPAN config)')
        elif rc == 0:
            print('listening OK (no packets in 5s — check SPAN config)')
        else:
            print(f'error — {out.strip()[:60]}')

    print()
    print('  If 0 packets: verify your switch SPAN/mirror port is active')
    print('  and connected to this sensor\'s monitoring NIC.')
    pause()


def test_codered_ai():
    """Test connection to CodeRed AI platform."""
    audit('test-codered-ai')
    config = load_config()
    endpoint = get_val(config, 'forwarding', 'siem_endpoint')
    port = get_val(config, 'forwarding', 'siem_port', '9200')

    header('TEST CODERED AI CONNECTION')

    if not endpoint:
        print('  CodeRed AI destination not configured.')
        print('  → Use option 8 to set the CodeRed AI IP and port.')
        pause()
        return

    print(f'  Target: {endpoint}:{port}\n')

    # Test 1: DNS/IP resolution
    print('  [1/3] Resolving address...', end=' ', flush=True)
    rc, _ = run_cmd(['ping', '-c', '1', '-W', '3', endpoint])
    if rc == 0:
        print('✓')
    else:
        print('✗ Cannot reach host')
        print(f'\n  Check: Is {endpoint} correct? Can this sensor reach that network?')
        pause()
        return

    # Test 2: TCP port connectivity
    print(f'  [2/3] Connecting to port {port}...', end=' ', flush=True)
    rc, out = run_cmd(
        ['bash', '-c', f'echo | timeout 5 bash -c "cat < /dev/null > /dev/tcp/{endpoint}/{port}" 2>&1'],
        timeout=10
    )
    if rc == 0:
        print('✓')
    else:
        # Try with openssl
        rc2, _ = run_cmd(
            ['bash', '-c', f'echo | timeout 5 openssl s_client -connect {endpoint}:{port} 2>/dev/null'],
            timeout=10
        )
        if rc2 == 0:
            print('✓ (TLS)')
        else:
            print(f'✗ Port {port} not reachable')
            print(f'\n  Check: Is CodeRed AI running? Is port {port} open on the firewall?')
            pause()
            return

    # Test 3: HTTP response (if Elasticsearch/OpenSearch)
    print('  [3/3] Testing service...', end=' ', flush=True)
    rc, out = run_cmd(
        ['bash', '-c', f'curl -sk --connect-timeout 5 --max-time 10 https://{endpoint}:{port}/ 2>/dev/null || curl -sk --connect-timeout 5 --max-time 10 http://{endpoint}:{port}/ 2>/dev/null'],
        timeout=15
    )
    if rc == 0 and out.strip():
        print('✓ Service responded')
    else:
        print('? (service may require authentication — this is normal)')

    print(f'\n  ✓ CodeRed AI at {endpoint}:{port} is reachable.')
    print('  Logs will be forwarded when NDR services are running.')
    pause()


def show_user_guide():
    """Display the user guide with paging."""
    audit('view:user-guide')

    GUIDE = """
============================================================
  CODERED AI SENSOR - USER GUIDE
============================================================

  OVERVIEW
  ────────
  This sensor passively monitors your network traffic for
  threats and anomalies. It needs two network connections:

    NIC 1 (ens32) = Management (SSH access + CodeRed AI forwarding)
    NIC 2+ (ens34, ens35...) = Monitor (receives mirrored/SPAN traffic)


  QUICK START
  ───────────
  1. Import the OVA into your hypervisor (VMware/Proxmox)
  2. Assign two NICs:
     - NIC 1 → your management network
     - NIC 2 → your SPAN/mirror port group
  3. Run: curl ... | sudo bash
  4. Run: sudo coderedndr
  5. Configure and start NDR


  HOW TO CONFIGURE SPAN / MIRROR PORT
  ────────────────────────────────────
  The sensor needs a copy of your network traffic. Configure
  your switch to mirror traffic to the port connected to the
  sensor's monitor NIC(s) (e.g., ens34, ens35).

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
    9200   │ Outbound   │ CodeRed AI forwarding
    53     │ Outbound   │ DNS
    123    │ Outbound   │ NTP
    22     │ Inbound    │ SSH management

  Sensor VM requirements:
    Minimum:      4 CPU,  8 GB RAM, 100 GB disk
    Recommended:  8 CPU, 16 GB RAM, 500 GB disk


  TROUBLESHOOTING
  ───────────────
  Not receiving traffic?
    1. Menu → 2 (Interfaces) → check ens34 shows PROMISC
    2. Verify SPAN is active on your switch
    3. VMware: check promiscuous mode on port group

  Cannot reach CodeRed AI?
    1. Menu → 4 (Diagnostics) → check CodeRed AI line
    2. Verify firewall allows sensor → CodeRed AI on port 9200

  High disk usage?
    1. Menu → 1 (Status) → check /nsm usage
    2. Increase VM disk in hypervisor if needed

  Services not running?
    1. Menu → 9 (Restart services) → restart all


  QUICK REFERENCE
  ───────────────
  Management:       sudo coderedndr
  Management NIC:    ens32 (needs IP address)
  Monitor NICs:      ens34, ens35... (SPAN ports, no IP)
  CodeRed AI default port: 9200

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

        print(f'\n  ── Page {page + 1}/{total_pages} ', end='')
        if page < total_pages - 1:
            print('── [Enter] Next  [q] Quit ──')
        else:
            print('── [q] Quit ──')

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

        # Get current IP
        _, ip_out = run_cmd(['hostname', '-I'])
        current_ip = ip_out.strip().split()[0] if ip_out.strip() else 'no IP'

        print(BANNER)
        print(f'  Sensor: {name} ({hostname})    Version: {version}')
        print(f'  IP: {current_ip}    {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

        # Setup checklist
        checklist = get_setup_checklist(config)
        incomplete = sum(1 for ok, _ in checklist if not ok)
        if incomplete > 0:
            print(f'\n  ── Setup Checklist ({incomplete} remaining) ──────────')
            for ok, desc in checklist:
                mark = '✓' if ok else '✗'
                print(f'   [{mark}] {desc}')

        print('\n  ── Status ──────────────────────────────────')
        print('   1. Sensor status overview')
        print('   2. Network interfaces')
        print('   3. View logs')
        print('   4. Diagnostics')

        print('\n  ── Configure ───────────────────────────────')
        print('   5. Network settings')
        print('   6. Hostname')
        print('   7. Monitor interfaces')
        print('   8. CodeRed AI destination')

        print('\n  ── NDR Services ────────────────────────────')
        print('   9. Start NDR (Zeek + Suricata + Filebeat)')
        print('  10. Stop NDR')
        print('  11. Restart services')
        print('  12. Test monitor interfaces')
        print('  13. Test CodeRed AI connection')

        print('\n  ── System ──────────────────────────────────')
        print('  14. Support bundle')
        print('  15. Reboot')
        print('  16. Shutdown')

        print('\n  ── Help ────────────────────────────────────')
        print('  17. User guide')

        print('\n   0. Exit')
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
            '9': start_ndr_services,
            '10': stop_ndr_services,
            '11': restart_services,
            '12': test_monitor_interface,
            '13': test_codered_ai,
            '14': generate_support_bundle,
            '15': do_reboot,
            '16': do_shutdown,
            '17': show_user_guide,
        }

        if choice == '0':
            if confirm('Exit?'):
                audit('exit')
                print('\n  Goodbye.\n')
                sys.exit(0)
        elif choice in actions:
            actions[choice]()
        elif choice:
            print(f'  Unknown option: {choice}')
            pause()


# ─── Entry Point ───────────────────────────────────────

def main():
    # Must be run as root
    if os.geteuid() != 0:
        print('\n  Error: coderedndr must be run as root.')
        print('  Usage: sudo coderedndr\n')
        sys.exit(1)

    setup_logging()
    audit('start')

    try:
        main_menu()
    except KeyboardInterrupt:
        print('\n')
        audit('exit:ctrl-c')
        sys.exit(0)


if __name__ == '__main__':
    main()

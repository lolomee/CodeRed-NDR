"""Allowed actions for the restricted sensor management shell."""

import os
import subprocess
import shutil
from datetime import datetime


def get_sensor_status() -> str:
    """Get overall sensor service status."""
    lines = []

    # SO status
    try:
        result = subprocess.run(
            ['so-status'], capture_output=True, text=True, timeout=30
        )
        lines.append("=== Security Onion Services ===")
        lines.append(result.stdout if result.returncode == 0 else "Unable to get SO status")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        lines.append("so-status: command not available")

    return "\n".join(lines)


def get_interface_status() -> str:
    """Get network interface information."""
    lines = ["=== Network Interfaces ==="]
    try:
        result = subprocess.run(
            ['ip', '-br', 'addr', 'show'], capture_output=True, text=True, timeout=10
        )
        lines.append(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        lines.append("Unable to get interface status")

    # Check monitor interface promisc
    try:
        result = subprocess.run(
            ['ip', '-d', 'link', 'show'], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if 'PROMISC' in line:
                lines.append(f"  (promiscuous) {line.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return "\n".join(lines)


def get_forwarding_status() -> str:
    """Check log forwarding health."""
    lines = ["=== Log Forwarding Status ==="]

    # Check Elastic Agent
    for svc in ['elastic-agent', 'filebeat', 'vector']:
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', svc],
                capture_output=True, text=True, timeout=10
            )
            status = result.stdout.strip()
            if status == 'active':
                lines.append(f"  {svc}: RUNNING")
            elif status == 'inactive':
                lines.append(f"  {svc}: stopped")
            # Don't show services that don't exist
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Check Docker containers for SO services
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=so-', '--format',
             '{{.Names}}\t{{.Status}}'],
            capture_output=True, text=True, timeout=15
        )
        if result.stdout.strip():
            lines.append("\n=== SO Containers ===")
            for line in result.stdout.strip().splitlines():
                lines.append(f"  {line}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return "\n".join(lines)


def get_disk_usage() -> str:
    """Get disk usage for important partitions."""
    lines = ["=== Disk Usage ==="]
    try:
        result = subprocess.run(
            ['df', '-h', '/', '/nsm', '/var/log'],
            capture_output=True, text=True, timeout=10
        )
        lines.append(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        lines.append("Unable to get disk usage")

    # NSM data sizes
    for path in ['/nsm/zeek', '/nsm/suricata', '/nsm/pcap']:
        if os.path.isdir(path):
            try:
                result = subprocess.run(
                    ['du', '-sh', path],
                    capture_output=True, text=True, timeout=30
                )
                lines.append(f"  {result.stdout.strip()}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    return "\n".join(lines)


def get_system_info() -> str:
    """Get basic system information."""
    lines = ["=== System Information ==="]

    # Hostname
    try:
        lines.append(f"  Hostname: {subprocess.run(['hostname'], capture_output=True, text=True, timeout=5).stdout.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Uptime
    try:
        result = subprocess.run(['uptime', '-p'], capture_output=True, text=True, timeout=5)
        lines.append(f"  Uptime: {result.stdout.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # CPU/Memory
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpus = sum(1 for line in f if line.startswith('processor'))
        lines.append(f"  CPUs: {cpus}")
    except IOError:
        pass

    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal'):
                    mem_kb = int(line.split()[1])
                    lines.append(f"  Memory: {mem_kb // 1024} MB")
                    break
    except IOError:
        pass

    # Version
    version_file = '/opt/codered/VERSION'
    if os.path.exists(version_file):
        with open(version_file) as f:
            lines.append(f"  CodeRed Version: {f.read().strip()}")

    # Last update
    update_log = '/var/log/codered/last-update.log'
    if os.path.exists(update_log):
        mtime = os.path.getmtime(update_log)
        lines.append(f"  Last Update: {datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')}")

    return "\n".join(lines)


def restart_services() -> str:
    """Restart all sensor services via SO wrapper."""
    try:
        result = subprocess.run(
            ['so-restart'], capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            return "All services restarted successfully."
        return f"Service restart completed with warnings:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return "Service restart timed out (5 min). Check so-status."
    except FileNotFoundError:
        return "so-restart command not found."


def restart_single_service(service: str) -> str:
    """Restart a specific SO service."""
    allowed = ['zeek', 'suricata', 'elastic-agent', 'logstash', 'filebeat']
    if service not in allowed:
        return f"Service '{service}' not in allowed list: {', '.join(allowed)}"

    cmd = f"so-{service}-restart"
    try:
        result = subprocess.run(
            [cmd], capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return f"{service} restarted successfully."
        return f"Failed to restart {service}: {result.stderr}"
    except FileNotFoundError:
        # Try systemctl as fallback
        try:
            result = subprocess.run(
                ['systemctl', 'restart', service],
                capture_output=True, text=True, timeout=60
            )
            return f"{service} restarted via systemctl."
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            return f"Failed to restart {service}: {e}"
    except subprocess.TimeoutExpired:
        return f"Restart of {service} timed out."


def view_logs(log_type: str = 'alerts', lines: int = 50) -> str:
    """View recent log entries (read-only)."""
    log_paths = {
        'alerts': '/nsm/suricata/eve.json',
        'zeek-dns': '/nsm/zeek/logs/current/dns.log',
        'zeek-conn': '/nsm/zeek/logs/current/conn.log',
        'zeek-http': '/nsm/zeek/logs/current/http.log',
        'system': '/var/log/syslog',
        'codered': '/var/log/codered/firstboot.log',
    }

    path = log_paths.get(log_type)
    if not path:
        return f"Unknown log type. Available: {', '.join(log_paths.keys())}"

    if not os.path.exists(path):
        return f"Log file not found: {path}"

    try:
        result = subprocess.run(
            ['tail', '-n', str(lines), path],
            capture_output=True, text=True, timeout=10
        )
        return f"=== Last {lines} lines of {path} ===\n{result.stdout}"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return f"Unable to read {path}"


def reboot_system() -> str:
    """Schedule system reboot."""
    try:
        subprocess.run(
            ['shutdown', '-r', '+1', 'CodeRed sensor reboot requested'],
            capture_output=True, timeout=10
        )
        return "System will reboot in 1 minute. Press Ctrl+C in the next 60 seconds to cancel."
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return f"Reboot failed: {e}"


def shutdown_system() -> str:
    """Schedule system shutdown."""
    try:
        subprocess.run(
            ['shutdown', '-h', '+1', 'CodeRed sensor shutdown requested'],
            capture_output=True, timeout=10
        )
        return "System will shut down in 1 minute."
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return f"Shutdown failed: {e}"

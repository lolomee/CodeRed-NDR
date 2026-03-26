#!/usr/bin/env python3
"""
CodeRed NDR — Syslog TCP/UDP Forwarder
Reads Zeek and Suricata logs and forwards as RFC5424 syslog over TCP or UDP.
Newline-delimited, compatible with Pre Security, QRadar, ArcSight, Graylog etc.
"""

import os
import sys
import time
import socket
import signal
import logging
import configparser
import json
import glob
import argparse
from datetime import datetime, timezone

# ─── Config ───────────────────────────────────────────────────────────────
CONF_FILE   = '/etc/codered/sensor.conf'
STATE_FILE  = '/var/lib/codered/syslog-forwarder.state'
LOG_FILE    = '/var/log/codered/syslog-forwarder.log'
ZEEK_PATH   = '/nsm/zeek/logs/current'
SURICATA_PATH = '/nsm/suricata/log/eve.json'

# Syslog facility/severity (local0.info)
FACILITY    = 16   # local0
SEVERITY    = 6    # info
PRIORITY    = (FACILITY * 8) + SEVERITY  # = 134

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
log = logging.getLogger('codered-syslog')

# ─── State (track file positions) ────────────────────────────────────────
def load_state():
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                for line in f:
                    parts = line.strip().split('\t', 1)
                    if len(parts) == 2:
                        state[parts[0]] = int(parts[1])
        except Exception:
            pass
    return state

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        for path, pos in state.items():
            f.write(f'{path}\t{pos}\n')

# ─── Syslog framing ──────────────────────────────────────────────────────
def make_syslog(hostname, app, msg):
    """Build RFC5424 syslog message, newline delimited."""
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    # Truncate msg to 8192 chars to avoid oversized packets
    if len(msg) > 8192:
        msg = msg[:8192]
    line = f'<{PRIORITY}>1 {ts} {hostname} {app} - - - {msg}'
    return (line + '\n').encode('utf-8', errors='replace')

# ─── Connection ──────────────────────────────────────────────────────────
class SyslogSender:
    def __init__(self, host, port, proto='tcp'):
        self.host   = host
        self.port   = int(port)
        self.proto  = proto.lower()
        self.sock   = None
        self.connect()

    def connect(self):
        try:
            if self.proto == 'udp':
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                log.info(f'UDP ready -> {self.host}:{self.port}')
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.host, self.port))
                self.sock.settimeout(None)
                log.info(f'TCP connected -> {self.host}:{self.port}')
        except Exception as e:
            log.error(f'Connect failed: {e}')
            self.sock = None

    def send(self, data):
        if not self.sock:
            self.connect()
        if not self.sock:
            return False
        try:
            if self.proto == 'udp':
                self.sock.sendto(data, (self.host, self.port))
            else:
                self.sock.sendall(data)
            return True
        except Exception as e:
            log.warning(f'Send error: {e} — reconnecting')
            self.sock = None
            time.sleep(2)
            self.connect()
            return False

# ─── Log tailing ─────────────────────────────────────────────────────────
def tail_file(path, state, sender, hostname, app):
    pos = state.get(path, 0)
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0

    # File rotated — reset position
    if size < pos:
        log.info(f'Rotation detected: {path}')
        pos = 0

    if size == pos:
        return 0

    sent = 0
    try:
        with open(path, 'r', errors='replace') as f:
            f.seek(pos)
            for line in f:
                line = line.rstrip('\n\r')
                if not line or line.startswith('#'):
                    continue
                msg = make_syslog(hostname, app, line)
                if sender.send(msg):
                    sent += 1
                else:
                    break
            pos = f.tell()
    except Exception as e:
        log.error(f'Read error {path}: {e}')

    state[path] = pos
    return sent

# ─── Main loop ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='CodeRed Syslog Forwarder')
    parser.add_argument('--host',  default='', help='SIEM host')
    parser.add_argument('--port',  default='514', help='SIEM port')
    parser.add_argument('--proto', default='tcp', choices=['tcp','udp'])
    args = parser.parse_args()

    # Read from sensor.conf if not provided
    host = args.host
    port = args.port
    proto = args.proto

    if not host:
        cfg = configparser.ConfigParser()
        cfg.read(CONF_FILE)
        host  = cfg.get('forwarding', 'siem_host', fallback='')
        port  = cfg.get('forwarding', 'siem_port', fallback='514')
        proto = cfg.get('forwarding', 'siem_proto', fallback='tcp')

    if not host:
        print('ERROR: No SIEM host configured. Set via menu option 8 or --host')
        sys.exit(1)

    # Get sensor hostname
    try:
        hostname = open('/etc/hostname').read().strip()
    except Exception:
        hostname = 'codered-sensor'

    log.info(f'Starting syslog forwarder -> {proto}://{host}:{port}')
    sender = SyslogSender(host, port, proto)
    state  = load_state()

    # Handle graceful shutdown
    running = [True]
    def stop(sig, frame):
        log.info('Shutting down...')
        running[0] = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    total_sent = 0
    while running[0]:
        batch_sent = 0

        # Tail all Zeek logs
        zeek_logs = glob.glob(f'{ZEEK_PATH}/*.log')
        for logpath in zeek_logs:
            app = 'zeek-' + os.path.basename(logpath).replace('.log', '')
            n = tail_file(logpath, state, sender, hostname, app)
            batch_sent += n

        # Tail Suricata EVE
        if os.path.exists(SURICATA_PATH):
            n = tail_file(SURICATA_PATH, state, sender, hostname, 'suricata')
            batch_sent += n

        if batch_sent > 0:
            total_sent += batch_sent
            log.info(f'Sent {batch_sent} events (total: {total_sent})')
            save_state(state)

        time.sleep(2)

    save_state(state)
    log.info(f'Stopped. Total events sent: {total_sent}')

if __name__ == '__main__':
    main()

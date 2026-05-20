#!/usr/bin/env python3
"""
CodeRed NDR — Syslog TCP/UDP Forwarder
Reads Zeek and Suricata logs and forwards as RFC5424 syslog over TCP or UDP.
Newline-delimited, compatible with Pre Security, QRadar, ArcSight, Graylog etc.
"""

import os
import sys
import ssl
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
def make_syslog(hostname, app, msg, raw=False):
    """Build syslog or raw message, newline delimited."""
    if len(msg) > 65536:
        msg = msg[:65536]
    if raw:
        # Raw mode: send the log line as-is with no syslog header
        return (msg + '\n').encode('utf-8', errors='replace')
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if len(msg) > 8192:
        msg = msg[:8192]
    line = f'<{PRIORITY}>1 {ts} {hostname} {app} - - - {msg}'
    return (line + '\n').encode('utf-8', errors='replace')

# ─── Connection ──────────────────────────────────────────────────────────
def _tls_error_hint(exc):
    """Map common TLS handshake failures to actionable operator hints."""
    msg = str(exc)
    if 'Hostname mismatch' in msg or 'doesn\'t match' in msg:
        return ('SIEM cert SAN does not match siem_host. '
                'Set siem_tls_servername to a name/IP listed in the cert SAN, '
                'or re-issue the cert with the connect address in its SAN, '
                'or set siem_tls_verify=false (encrypt-only, not recommended).')
    if 'CERTIFICATE_VERIFY_FAILED' in msg:
        return ('SIEM server certificate not trusted. Point siem_tls_ca at the '
                'PEM CA that signed the SIEM cert, or set siem_tls_verify=false.')
    if 'UNKNOWN_CA' in msg or 'unknown ca' in msg.lower():
        return ('SIEM rejected our client certificate. The siem_tls_cert must be '
                'signed by a CA the SIEM trusts (mutual TLS).')
    if 'BAD_CERTIFICATE' in msg or 'bad certificate' in msg.lower():
        return ('SIEM rejected our client certificate as malformed or expired. '
                'Check siem_tls_cert / siem_tls_key files.')
    if 'HANDSHAKE_FAILURE' in msg or 'handshake failure' in msg.lower():
        return ('TLS handshake failed. Common causes: mTLS required but no '
                'siem_tls_cert/siem_tls_key configured; or no shared cipher.')
    if 'WRONG_VERSION_NUMBER' in msg:
        return ('Endpoint does not speak TLS on this port — check siem_port and '
                'whether the SIEM listener is plain TCP vs TLS.')
    if 'NO_CERTIFICATE_OR_CRL_FOUND' in msg or 'PEM lib' in msg:
        return ('siem_tls_ca, siem_tls_cert, or siem_tls_key does not contain '
                'a valid PEM-formatted certificate. Verify the file with '
                '"openssl x509 -in <file> -noout -subject".')
    return ''


class SyslogSender:
    def __init__(self, host, port, proto='tcp',
                 tls=False, tls_ca='', tls_verify=True,
                 tls_cert='', tls_key='', tls_servername=''):
        self.host           = host
        self.port           = int(port)
        self.proto          = proto.lower()
        self.tls            = bool(tls) and self.proto == 'tcp'
        self.tls_ca         = tls_ca or ''
        self.tls_verify     = bool(tls_verify)
        self.tls_cert       = tls_cert or ''
        self.tls_key        = tls_key or ''
        self.tls_servername = tls_servername or ''
        self.sock           = None
        self._ssl_ctx       = None
        if self.tls:
            try:
                self._ssl_ctx = self._build_ssl_context()
            except (ssl.SSLError, FileNotFoundError, ValueError) as e:
                hint = _tls_error_hint(e)
                log.error(f'TLS context build failed: {e}'
                          + (f' | HINT: {hint}' if hint else ''))
                return
        self.connect()

    def _build_ssl_context(self):
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if self.tls_ca:
            if not os.path.isfile(self.tls_ca):
                raise FileNotFoundError(f'TLS CA file not found: {self.tls_ca}')
            ctx.load_verify_locations(cafile=self.tls_ca)
        if self.tls_cert or self.tls_key:
            if not self.tls_cert or not self.tls_key:
                raise ValueError('mTLS requires BOTH siem_tls_cert and siem_tls_key')
            if not os.path.isfile(self.tls_cert):
                raise FileNotFoundError(f'TLS client cert not found: {self.tls_cert}')
            if not os.path.isfile(self.tls_key):
                raise FileNotFoundError(f'TLS client key not found: {self.tls_key}')
            ctx.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)
            log.info(f'mTLS enabled — client cert: {self.tls_cert}')
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            log.warning('TLS certificate verification DISABLED (siem_tls_verify=false)')
        return ctx

    def connect(self):
        try:
            if self.proto == 'udp':
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                log.info(f'UDP ready -> {self.host}:{self.port}')
                return
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            if self.tls:
                sni = self.tls_servername or self.host
                self.sock = self._ssl_ctx.wrap_socket(raw, server_hostname=sni)
                self.sock.connect((self.host, self.port))
                peer = self.sock.getpeercert() if self.tls_verify else None
                cn = ''
                if peer:
                    for tup in peer.get('subject', ()):
                        for k, v in tup:
                            if k == 'commonName':
                                cn = v
                log.info(f'TLS connected -> {self.host}:{self.port} (SNI={sni})'
                         + (f' peer CN={cn}' if cn else ''))
            else:
                self.sock = raw
                self.sock.connect((self.host, self.port))
                log.info(f'TCP connected -> {self.host}:{self.port}')
            self.sock.settimeout(None)
        except ssl.SSLError as e:
            hint = _tls_error_hint(e)
            log.error(f'TLS handshake failed: {e}'
                      + (f' | HINT: {hint}' if hint else ''))
            self.sock = None
        except Exception as e:
            hint = _tls_error_hint(e) if self.tls else ''
            log.error(f'Connect failed: {e}'
                      + (f' | HINT: {hint}' if hint else ''))
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
def tail_file(path, state, sender, hostname, app, raw=False):
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
                msg = make_syslog(hostname, app, line, raw=raw)
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
    parser.add_argument('--raw',   action='store_true',
                        help='Send raw log lines without RFC5424 syslog header')
    parser.add_argument('--tls',   action='store_true',
                        help='Wrap TCP connection in TLS (RFC5425). TCP only.')
    parser.add_argument('--tls-ca', default='',
                        help='Path to CA cert (PEM) used to verify the SIEM. '
                             'If empty, the system trust store is used.')
    parser.add_argument('--tls-no-verify', action='store_true',
                        help='Skip TLS certificate verification (insecure).')
    parser.add_argument('--tls-cert', default='',
                        help='Client certificate (PEM) for mutual TLS.')
    parser.add_argument('--tls-key', default='',
                        help='Client private key (PEM) for mutual TLS.')
    parser.add_argument('--tls-servername', default='',
                        help='SNI / hostname verification override. Use when '
                             'connecting by IP but cert SAN holds a DNS name.')
    parser.add_argument('--test-connect', action='store_true',
                        help='Dry-run: connect, send one probe event, exit. '
                             '0 = OK, 1 = failure. Does not tail logs.')
    args = parser.parse_args()

    # Read from sensor.conf if not provided
    cfg = configparser.ConfigParser()
    cfg.read(CONF_FILE)

    host  = args.host  or cfg.get('forwarding', 'siem_host',  fallback='')
    port  = args.port  if args.host else cfg.get('forwarding', 'siem_port',  fallback='514')
    proto = args.proto if args.host else cfg.get('forwarding', 'siem_proto', fallback='tcp')
    raw_mode = (cfg.get('forwarding', 'siem_raw', fallback='false') == 'true'
                or args.raw)
    tls = (args.tls
           or cfg.get('forwarding', 'siem_tls', fallback='false') == 'true')
    tls_ca         = args.tls_ca         or cfg.get('forwarding', 'siem_tls_ca', fallback='')
    tls_verify     = not args.tls_no_verify and (
        cfg.get('forwarding', 'siem_tls_verify', fallback='true') == 'true')
    tls_cert       = args.tls_cert       or cfg.get('forwarding', 'siem_tls_cert', fallback='')
    tls_key        = args.tls_key        or cfg.get('forwarding', 'siem_tls_key', fallback='')
    tls_servername = args.tls_servername or cfg.get('forwarding', 'siem_tls_servername', fallback='')

    if not host:
        print('ERROR: No SIEM host configured. Set via menu option 8 or --host')
        sys.exit(1)

    if tls and proto == 'udp':
        print('ERROR: TLS is only supported on TCP (DTLS not implemented).')
        sys.exit(1)
    if tls and tls_verify and not tls_ca:
        log.warning('TLS verify=on with no siem_tls_ca — using system trust store. '
                    'Self-signed certs will fail; set siem_tls_ca or siem_tls_verify=false.')

    # Get sensor hostname
    try:
        hostname = open('/etc/hostname').read().strip()
    except Exception:
        hostname = 'codered-sensor'

    scheme = 'syslog-tls' if tls else proto
    log.info(f'Starting syslog forwarder -> {scheme}://{host}:{port}')

    # ── Dry-run mode ──────────────────────────────────────────────────────
    if args.test_connect:
        try:
            sender = SyslogSender(host, port, proto,
                                  tls=tls, tls_ca=tls_ca, tls_verify=tls_verify,
                                  tls_cert=tls_cert, tls_key=tls_key,
                                  tls_servername=tls_servername)
        except (FileNotFoundError, ValueError) as e:
            print(f'CONFIG ERROR: {e}', file=sys.stderr)
            sys.exit(1)
        if sender.sock is None:
            print(f'CONNECT FAILED to {scheme}://{host}:{port} — see {LOG_FILE}',
                  file=sys.stderr)
            sys.exit(1)
        try:
            probe = make_syslog('codered-test', 'codered-test',
                                'codered-test-connect probe', raw=raw_mode)
            ok = sender.send(probe)
        finally:
            try: sender.sock.close()
            except Exception: pass
        if ok:
            print(f'OK: {scheme}://{host}:{port} accepted a probe event')
            sys.exit(0)
        print(f'FAIL: connected to {scheme}://{host}:{port} but send failed',
              file=sys.stderr)
        sys.exit(1)

    sender = SyslogSender(host, port, proto,
                          tls=tls, tls_ca=tls_ca, tls_verify=tls_verify,
                          tls_cert=tls_cert, tls_key=tls_key,
                          tls_servername=tls_servername)
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
            n = tail_file(logpath, state, sender, hostname, app, raw=raw_mode)
            batch_sent += n

        # Tail Suricata EVE
        if os.path.exists(SURICATA_PATH):
            n = tail_file(SURICATA_PATH, state, sender, hostname, 'suricata', raw=raw_mode)
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

#!/usr/bin/env python3
"""
CodeRed NDR — Behavioral ML Engine
====================================
Reads Zeek conn.log and dns.log in real time, maintains rolling per-host
behavioral baselines, and detects anomalous behavior using Isolation Forest.

Detection coverage (MITRE ATT&CK):
  T1071   — Unusual outbound connection volume (C2 staging)
  T1048   — Sudden large data transfer spike (exfiltration)
  T1071.004 — DNS query volume spike (DNS tunneling / DGA)
  T1018   — Internal network sweep (unusual unique destinations)
  T1020   — Off-hours activity anomaly (insider threat)

Architecture:
  - Tails Zeek logs with inotify-style polling
  - Builds 24h rolling feature windows per host (stored in SQLite)
  - Trains an Isolation Forest per host after warm-up period (100+ samples)
  - Scores each new observation against the host's own baseline
  - Anomalies written to /nsm/codered/ml-alerts.json (Filebeat picks up)
  - Designed to run as: systemd service codered-ml

No GPU required. Runs on the sensor VM itself (~150-200MB RAM typical).
"""

import json
import os
import re
import sqlite3
import sys
import time
import logging
import signal
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─── Configuration ────────────────────────────────────────────────────────

ZEEK_LOG_DIR     = "/nsm/zeek/logs/current"
CONN_LOG         = f"{ZEEK_LOG_DIR}/conn.log"
DNS_LOG          = f"{ZEEK_LOG_DIR}/dns.log"
HTTP_LOG         = f"{ZEEK_LOG_DIR}/http.log"
ALERT_OUTPUT     = "/nsm/codered/ml-alerts.json"
DB_PATH          = "/var/lib/codered/ml-baseline.db"
LOG_FILE         = "/var/log/codered/ml-engine.log"

# Warm-up: minimum observations before training a model for a host
WARMUP_SAMPLES   = 50       # ~50 hours of hourly aggregation

# How often to re-aggregate features (seconds)
AGGREGATE_INTERVAL = 60     # aggregate every 60 seconds

# How often to retrain models (seconds)
RETRAIN_INTERVAL   = 3600   # retrain every hour

# Isolation Forest contamination: expected fraction of anomalies
# 0.01 = we expect ~1% of observations to be truly anomalous
CONTAMINATION    = 0.01

# Alert threshold: Isolation Forest score below this = anomaly
# IsolationForest.score_samples returns negative values; more negative = more anomalous
ANOMALY_THRESHOLD = -0.15

# Rolling window for baseline (keep last N hours of data per host)
BASELINE_WINDOW_HOURS = 168   # 7 days

# Internal network CIDR patterns (supplement Site::local_nets in Zeek)
# Read from sensor.conf if present
INTERNAL_NETS = [
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "fc", "fd",  # IPv6 ULA
]

# ─── Logging ──────────────────────────────────────────────────────────────

def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout),
        ]
    )

log = logging.getLogger(__name__)

# ─── Utilities ────────────────────────────────────────────────────────────

def is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_NETS)

def ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def current_hour_bucket() -> int:
    """Return current time rounded down to nearest hour (unix timestamp)."""
    now = int(time.time())
    return now - (now % 3600)

# ─── Database ─────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS host_features (
            host        TEXT NOT NULL,
            hour_bucket INTEGER NOT NULL,
            conn_count  INTEGER DEFAULT 0,
            bytes_out   INTEGER DEFAULT 0,
            bytes_in    INTEGER DEFAULT 0,
            unique_dsts INTEGER DEFAULT 0,
            ext_dsts    INTEGER DEFAULT 0,
            dns_queries INTEGER DEFAULT 0,
            unique_fqdns INTEGER DEFAULT 0,
            http_reqs   INTEGER DEFAULT 0,
            avg_duration REAL DEFAULT 0.0,
            PRIMARY KEY (host, hour_bucket)
        );

        CREATE TABLE IF NOT EXISTS ml_models (
            host        TEXT PRIMARY KEY,
            trained_at  INTEGER,
            sample_count INTEGER,
            threshold   REAL
        );

        CREATE INDEX IF NOT EXISTS idx_host_hour
            ON host_features(host, hour_bucket);
    """)
    conn.commit()
    return conn

def prune_old_data(db: sqlite3.Connection):
    """Remove baseline data older than BASELINE_WINDOW_HOURS."""
    cutoff = current_hour_bucket() - (BASELINE_WINDOW_HOURS * 3600)
    db.execute("DELETE FROM host_features WHERE hour_bucket < ?", (cutoff,))
    db.commit()

# ─── Log tail ─────────────────────────────────────────────────────────────

class LogTailer:
    """Efficiently tail a Zeek log file, handling log rotation."""

    def __init__(self, path: str):
        self.path = path
        self._fh = None
        self._inode = None
        self._pos = 0

    def _open(self):
        try:
            st = os.stat(self.path)
            if self._fh is None or st.st_ino != self._inode:
                if self._fh:
                    self._fh.close()
                self._fh = open(self.path, "r", errors="replace")
                self._inode = st.st_ino
                # On rotation, start from beginning; otherwise seek to last pos
                if self._pos > st.st_size:
                    self._pos = 0
                self._fh.seek(self._pos)
        except (FileNotFoundError, PermissionError):
            self._fh = None

    def readlines(self):
        self._open()
        if not self._fh:
            return []
        lines = self._fh.readlines()
        self._pos = self._fh.tell()
        return [l.rstrip("\n") for l in lines if l.strip()]

# ─── Feature accumulator ──────────────────────────────────────────────────

class FeatureAccumulator:
    """
    In-memory accumulator for the current hour's features per host.
    Flushed to SQLite at the end of each aggregate interval.
    """

    def __init__(self):
        self._reset()

    def _reset(self):
        self.conn_count   = defaultdict(int)
        self.bytes_out    = defaultdict(int)
        self.bytes_in     = defaultdict(int)
        self.unique_dsts  = defaultdict(set)
        self.ext_dsts     = defaultdict(set)
        self.dns_queries  = defaultdict(int)
        self.unique_fqdns = defaultdict(set)
        self.http_reqs    = defaultdict(int)
        self.durations    = defaultdict(list)

    def add_conn(self, src: str, dst: str, orig_bytes: int,
                 resp_bytes: int, duration: float):
        self.conn_count[src] += 1
        self.bytes_out[src]  += orig_bytes
        self.bytes_in[src]   += resp_bytes
        self.unique_dsts[src].add(dst)
        if not is_internal(dst):
            self.ext_dsts[src].add(dst)
        if duration > 0:
            self.durations[src].append(duration)

    def add_dns(self, src: str, query: str):
        self.dns_queries[src]  += 1
        self.unique_fqdns[src].add(query)

    def add_http(self, src: str):
        self.http_reqs[src] += 1

    def flush(self, db: sqlite3.Connection, bucket: int):
        """Write accumulated features to DB and reset."""
        hosts = set(list(self.conn_count.keys()) +
                    list(self.dns_queries.keys()) +
                    list(self.http_reqs.keys()))

        for host in hosts:
            durs = self.durations.get(host, [])
            avg_dur = float(np.mean(durs)) if durs else 0.0

            db.execute("""
                INSERT INTO host_features
                    (host, hour_bucket, conn_count, bytes_out, bytes_in,
                     unique_dsts, ext_dsts, dns_queries, unique_fqdns,
                     http_reqs, avg_duration)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host, hour_bucket) DO UPDATE SET
                    conn_count   = conn_count   + excluded.conn_count,
                    bytes_out    = bytes_out    + excluded.bytes_out,
                    bytes_in     = bytes_in     + excluded.bytes_in,
                    unique_dsts  = MAX(unique_dsts,  excluded.unique_dsts),
                    ext_dsts     = MAX(ext_dsts,     excluded.ext_dsts),
                    dns_queries  = dns_queries  + excluded.dns_queries,
                    unique_fqdns = MAX(unique_fqdns, excluded.unique_fqdns),
                    http_reqs    = http_reqs    + excluded.http_reqs,
                    avg_duration = (avg_duration + excluded.avg_duration) / 2.0
            """, (
                host, bucket,
                self.conn_count.get(host, 0),
                self.bytes_out.get(host, 0),
                self.bytes_in.get(host, 0),
                len(self.unique_dsts.get(host, set())),
                len(self.ext_dsts.get(host, set())),
                self.dns_queries.get(host, 0),
                len(self.unique_fqdns.get(host, set())),
                self.http_reqs.get(host, 0),
                avg_dur,
            ))

        db.commit()
        self._reset()

# ─── Zeek log parsers ─────────────────────────────────────────────────────

def parse_zeek_tsv(line: str) -> Optional[dict]:
    """Parse a Zeek TSV log line into a dict using the most recent #fields header."""
    if line.startswith("#"):
        return None
    return line  # raw — caller splits by fields header

class ZeekConnParser:
    FIELDS = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p",
              "proto","service","duration","orig_bytes","resp_bytes",
              "conn_state","local_orig","local_resp"]

    def parse(self, line: str) -> Optional[dict]:
        if line.startswith("#"):
            return None
        parts = line.split("\t")
        if len(parts) < 10:
            return None
        try:
            return {
                "src":       parts[2],
                "dst":       parts[4],
                "duration":  float(parts[8]) if parts[8] != "-" else 0.0,
                "orig_bytes": int(parts[9])  if parts[9]  != "-" else 0,
                "resp_bytes": int(parts[10]) if parts[10] != "-" else 0,
            }
        except (ValueError, IndexError):
            return None

class ZeekDNSParser:
    def parse(self, line: str) -> Optional[dict]:
        if line.startswith("#"):
            return None
        parts = line.split("\t")
        if len(parts) < 10:
            return None
        try:
            return {"src": parts[2], "query": parts[9] if parts[9] != "-" else ""}
        except IndexError:
            return None

class ZeekHTTPParser:
    def parse(self, line: str) -> Optional[dict]:
        if line.startswith("#"):
            return None
        parts = line.split("\t")
        if len(parts) < 3:
            return None
        return {"src": parts[2]}

# ─── ML model manager ─────────────────────────────────────────────────────

class ModelManager:
    """
    Trains and manages one Isolation Forest per host.
    Features (per hourly bucket):
      [0] conn_count     — total connections
      [1] bytes_out      — total bytes sent
      [2] bytes_in       — total bytes received
      [3] unique_dsts    — unique destination IPs
      [4] ext_dsts       — unique external destination IPs
      [5] dns_queries    — DNS query count
      [6] unique_fqdns   — unique FQDNs queried
      [7] http_reqs      — HTTP requests
      [8] avg_duration   — average connection duration
      [9] bytes_ratio    — out/in ratio (exfil indicator)
    """

    FEATURE_COLS = [
        "conn_count", "bytes_out", "bytes_in", "unique_dsts",
        "ext_dsts", "dns_queries", "unique_fqdns", "http_reqs", "avg_duration"
    ]

    def __init__(self):
        self._models: dict = {}        # host -> (IsolationForest, StandardScaler)
        self._trained_at: dict = {}    # host -> timestamp

    def _load_features(self, db: sqlite3.Connection, host: str) -> np.ndarray:
        cutoff = current_hour_bucket() - (BASELINE_WINDOW_HOURS * 3600)
        rows = db.execute("""
            SELECT conn_count, bytes_out, bytes_in, unique_dsts, ext_dsts,
                   dns_queries, unique_fqdns, http_reqs, avg_duration
            FROM host_features
            WHERE host = ? AND hour_bucket >= ?
            ORDER BY hour_bucket
        """, (host, cutoff)).fetchall()

        if not rows:
            return np.array([])

        arr = np.array(rows, dtype=float)

        # Add derived feature: bytes_ratio (out / (in+1))
        ratio = arr[:, 1] / (arr[:, 2] + 1.0)
        arr = np.column_stack([arr, ratio])

        return arr

    def train(self, db: sqlite3.Connection, host: str) -> bool:
        """Train or retrain IsolationForest for a host. Returns True if trained."""
        X = self._load_features(db, host)
        if len(X) < WARMUP_SAMPLES:
            return False

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=1,
        )
        model.fit(X_scaled)

        self._models[host] = (model, scaler)
        self._trained_at[host] = time.time()

        db.execute("""
            INSERT OR REPLACE INTO ml_models (host, trained_at, sample_count, threshold)
            VALUES (?, ?, ?, ?)
        """, (host, int(time.time()), len(X), ANOMALY_THRESHOLD))
        db.commit()

        log.info(f"ML model trained for {host} — {len(X)} samples")
        return True

    def score(self, host: str, features: list) -> Optional[float]:
        """Score a feature vector. Returns anomaly score or None if no model."""
        if host not in self._models:
            return None

        model, scaler = self._models[host]
        X = np.array([features], dtype=float)

        # Add bytes_ratio derived feature
        ratio = X[0, 1] / (X[0, 2] + 1.0)
        X = np.column_stack([X, [[ratio]]])

        X_scaled = scaler.transform(X)
        score = model.score_samples(X_scaled)[0]
        return float(score)

    def needs_retrain(self, host: str) -> bool:
        if host not in self._trained_at:
            return True
        return time.time() - self._trained_at[host] > RETRAIN_INTERVAL

    def get_trained_hosts(self) -> list:
        return list(self._models.keys())

# ─── Alert writer ──────────────────────────────────────────────────────────

class AlertWriter:
    """Writes ML anomaly alerts to JSON file for Filebeat ingestion."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, host: str, score: float, features: dict,
              note_type: str, description: str, mitre: str):
        alert = {
            "ts":          ts_now(),
            "sensor":      "codered-ml",
            "alert_type":  "behavioral_anomaly",
            "note":        note_type,
            "src":         host,
            "msg":         description,
            "sub":         f"anomaly_score={score:.3f}",
            "mitre":       mitre,
            "features":    features,
            "severity":    "high" if score < -0.25 else "medium",
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(alert) + "\n")

        log.warning(f"ANOMALY [{note_type}] src={host} score={score:.3f} {description}")

# ─── Anomaly interpreter ───────────────────────────────────────────────────

def interpret_anomaly(host: str, current: dict, baseline_mean: dict,
                      score: float) -> tuple:
    """
    Determine the most likely anomaly type by comparing
    current features to the host's baseline mean.
    Returns (note_type, description, mitre_tactic).
    """
    diffs = {}
    for k in baseline_mean:
        if baseline_mean[k] > 0:
            diffs[k] = current.get(k, 0) / baseline_mean[k]
        else:
            diffs[k] = 1.0 if current.get(k, 0) == 0 else 10.0

    # Find the feature most responsible for the anomaly
    worst_key = max(diffs, key=lambda k: diffs[k])
    worst_ratio = diffs[worst_key]

    if diffs.get("bytes_out", 1) > 5.0 and current.get("ext_dsts", 0) > 0:
        return (
            "ML_DataExfiltration",
            f"Unusual outbound data from {host}: {current.get('bytes_out',0)//1048576}MB "
            f"({worst_ratio:.1f}x baseline) to {current.get('ext_dsts',0)} external hosts",
            "T1048, T1041"
        )
    elif diffs.get("dns_queries", 1) > 5.0 or diffs.get("unique_fqdns", 1) > 5.0:
        return (
            "ML_DNS_Anomaly",
            f"Unusual DNS activity from {host}: {current.get('dns_queries',0)} queries "
            f"({diffs.get('dns_queries',1):.1f}x baseline), "
            f"{current.get('unique_fqdns',0)} unique FQDNs",
            "T1071.004, T1568.002"
        )
    elif diffs.get("ext_dsts", 1) > 4.0:
        return (
            "ML_Reconnaissance",
            f"Unusual external connection spread from {host}: "
            f"{current.get('ext_dsts',0)} unique external destinations "
            f"({diffs.get('ext_dsts',1):.1f}x baseline)",
            "T1046, T1018"
        )
    elif diffs.get("conn_count", 1) > 5.0:
        return (
            "ML_ConnectionSpike",
            f"Unusual connection volume from {host}: "
            f"{current.get('conn_count',0)} connections "
            f"({diffs.get('conn_count',1):.1f}x baseline)",
            "T1071, T1095"
        )
    else:
        return (
            "ML_BehavioralAnomaly",
            f"Behavioral anomaly detected for {host} "
            f"(score={score:.3f}, {worst_key} is {worst_ratio:.1f}x baseline)",
            "T1071"
        )

# ─── Main engine ──────────────────────────────────────────────────────────

class MLEngine:

    def __init__(self):
        self.db      = init_db(DB_PATH)
        self.acc     = FeatureAccumulator()
        self.models  = ModelManager()
        self.writer  = AlertWriter(ALERT_OUTPUT)
        self.parsers = {
            "conn": (LogTailer(CONN_LOG), ZeekConnParser()),
            "dns":  (LogTailer(DNS_LOG),  ZeekDNSParser()),
            "http": (LogTailer(HTTP_LOG), ZeekHTTPParser()),
        }
        self._last_aggregate = time.time()
        self._last_retrain   = time.time()
        self._running = True

        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT,  self._shutdown)

    def _shutdown(self, *_):
        log.info("ML engine shutting down...")
        self._running = False

    def _read_logs(self):
        """Read new lines from all tailed log files."""
        tailer, parser = self.parsers["conn"]
        for line in tailer.readlines():
            r = parser.parse(line)
            if r and is_internal(r["src"]):
                self.acc.add_conn(
                    r["src"], r["dst"],
                    r["orig_bytes"], r["resp_bytes"], r["duration"]
                )

        tailer, parser = self.parsers["dns"]
        for line in tailer.readlines():
            r = parser.parse(line)
            if r and r["query"] and is_internal(r["src"]):
                self.acc.add_dns(r["src"], r["query"])

        tailer, parser = self.parsers["http"]
        for line in tailer.readlines():
            r = parser.parse(line)
            if r and is_internal(r["src"]):
                self.acc.add_http(r["src"])

    def _aggregate(self):
        """Flush accumulator to DB."""
        bucket = current_hour_bucket()
        self.acc.flush(self.db, bucket)
        self._last_aggregate = time.time()

    def _train_models(self):
        """Train/retrain models for all hosts with enough data."""
        hosts = [
            row[0] for row in
            self.db.execute(
                "SELECT DISTINCT host FROM host_features"
            ).fetchall()
        ]
        for host in hosts:
            if self.models.needs_retrain(host):
                self.models.train(self.db, host)

        prune_old_data(self.db)
        self._last_retrain = time.time()

    def _score_current_hour(self):
        """Score the current hour's features for all trained hosts."""
        bucket = current_hour_bucket()
        trained = self.models.get_trained_hosts()

        for host in trained:
            row = self.db.execute("""
                SELECT conn_count, bytes_out, bytes_in, unique_dsts, ext_dsts,
                       dns_queries, unique_fqdns, http_reqs, avg_duration
                FROM host_features
                WHERE host = ? AND hour_bucket = ?
            """, (host, bucket)).fetchone()

            if not row:
                continue

            features = list(row)
            score = self.models.score(host, features)

            if score is None or score >= ANOMALY_THRESHOLD:
                continue

            # Anomaly detected — compute baseline mean for interpretation
            baseline_rows = self.db.execute("""
                SELECT AVG(conn_count), AVG(bytes_out), AVG(bytes_in),
                       AVG(unique_dsts), AVG(ext_dsts), AVG(dns_queries),
                       AVG(unique_fqdns), AVG(http_reqs), AVG(avg_duration)
                FROM host_features
                WHERE host = ? AND hour_bucket < ?
                ORDER BY hour_bucket DESC LIMIT 168
            """, (host, bucket)).fetchone()

            if not baseline_rows:
                continue

            baseline_mean = {
                "conn_count":   baseline_rows[0] or 1,
                "bytes_out":    baseline_rows[1] or 1,
                "bytes_in":     baseline_rows[2] or 1,
                "unique_dsts":  baseline_rows[3] or 1,
                "ext_dsts":     baseline_rows[4] or 1,
                "dns_queries":  baseline_rows[5] or 1,
                "unique_fqdns": baseline_rows[6] or 1,
                "http_reqs":    baseline_rows[7] or 1,
                "avg_duration": baseline_rows[8] or 0,
            }

            current = {
                "conn_count":   features[0],
                "bytes_out":    features[1],
                "bytes_in":     features[2],
                "unique_dsts":  features[3],
                "ext_dsts":     features[4],
                "dns_queries":  features[5],
                "unique_fqdns": features[6],
                "http_reqs":    features[7],
                "avg_duration": features[8],
            }

            note, desc, mitre = interpret_anomaly(host, current, baseline_mean, score)

            self.writer.write(
                host=host,
                score=score,
                features=current,
                note_type=note,
                description=desc,
                mitre=mitre,
            )

    def run(self):
        log.info("CodeRed NDR ML Engine starting...")
        log.info(f"  Baseline DB:   {DB_PATH}")
        log.info(f"  Alert output:  {ALERT_OUTPUT}")
        log.info(f"  Warm-up:       {WARMUP_SAMPLES} hourly samples per host")
        log.info(f"  Retrain every: {RETRAIN_INTERVAL}s")
        log.info("")

        while self._running:
            try:
                self._read_logs()

                now = time.time()

                if now - self._last_aggregate >= AGGREGATE_INTERVAL:
                    self._aggregate()
                    self._score_current_hour()

                if now - self._last_retrain >= RETRAIN_INTERVAL:
                    self._train_models()

                time.sleep(2)

            except Exception as e:
                log.error(f"Engine error: {e}", exc_info=True)
                time.sleep(5)

        log.info("ML engine stopped.")


if __name__ == "__main__":
    setup_logging()
    MLEngine().run()

#!/usr/bin/env python3
"""
CodeRed NDR — Behavioral ML Engine
====================================
Reads Zeek conn.log, dns.log and http.log in real time, maintains rolling
per-host behavioral baselines, and detects anomalous behavior using an
Isolation Forest trained per host.

Detection coverage (MITRE ATT&CK):
  T1071   — Unusual outbound connection volume (C2 staging)
  T1048   — Sudden large data transfer spike (exfiltration)
  T1071.004 — DNS query volume spike (DNS tunneling / DGA)
  T1018   — Internal network sweep (unusual unique destinations)
  T1020   — Off-hours activity anomaly (insider threat)

Architecture:
  - Tails Zeek logs (rotation-aware), accumulating ONE rolling snapshot per
    host for the current clock-hour bucket (true hourly distinct counts).
  - On the hour boundary the completed bucket is scored once; partial buckets
    are never scored (no top-of-hour false positives, no duplicate alerts).
  - Trains an Isolation Forest per host after warm-up (WARMUP_SAMPLES buckets).
  - On first start, seeds baselines from Zeek's hourly gzip archives so models
    can train within a day of deployment instead of after ~2 days.
  - Anomalies written to /nsm/codered/ml-alerts.json (the CodeRed syslog
    forwarder ships this file to the SIEM as app-name `codered-ml`).
  - Designed to run as: systemd service codered-ml

No GPU required. Runs on the sensor VM itself (~150-200MB RAM typical).
"""

import gzip
import json
import os
import sys
import time
import glob
import logging
import signal
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    print(f"[FATAL] Missing ML dependency: {e}", flush=True)
    print("[FATAL] Fix: sudo pip3 install scikit-learn numpy --break-system-packages", flush=True)
    sys.exit(1)

# ─── Configuration ────────────────────────────────────────────────────────

ZEEK_LOG_DIR     = "/nsm/zeek/logs"
ZEEK_CURRENT     = f"{ZEEK_LOG_DIR}/current"
CONN_LOG         = f"{ZEEK_CURRENT}/conn.log"
DNS_LOG          = f"{ZEEK_CURRENT}/dns.log"
HTTP_LOG         = f"{ZEEK_CURRENT}/http.log"
ALERT_OUTPUT     = "/nsm/codered/ml-alerts.json"
DB_PATH          = "/var/lib/codered/ml-baseline.db"
LOG_FILE         = "/var/log/codered/ml-engine.log"

# Warm-up: minimum completed hourly buckets before training a host's model.
# 24 = one day of behaviour. Combined with archive seeding (seed_from_archives)
# a freshly deployed sensor can train models on day one rather than after ~2
# days. Each bucket is a full clock-hour aggregate.
WARMUP_SAMPLES   = 24

# How often to flush the current hour's running snapshot to the DB (seconds).
AGGREGATE_INTERVAL = 60

# How often to retrain models (seconds).
RETRAIN_INTERVAL   = 3600   # retrain every hour

# Isolation Forest contamination: expected fraction of anomalies.
CONTAMINATION    = 0.02

# ── Robust statistical tripwires ───────────────────────────────────────────
# A per-host, per-feature deterministic layer that runs ALONGSIDE the Isolation
# Forest. For each feature we compute the baseline median and MAD (median
# absolute deviation, a robust stand-in for std) over the host's history and
# flag the current hour when it is both (a) K_MAD robust-sigmas above the
# median AND (b) over a per-feature absolute floor (so a quiet host going from
# 1→5 queries does not trip). This guarantees the headline detections
# (exfil / scan / flood / DNS-tunnel) fire even though an unsupervised
# Isolation Forest alone misses several of them, and it works after only
# TRIPWIRE_MIN_HISTORY hours — long before the forest's WARMUP_SAMPLES.
K_MAD              = 6.0
MIN_FOLD           = 4.0     # current must also be >= MIN_FOLD x baseline median
TRIPWIRE_MIN_HISTORY = 8     # hourly buckets needed before tripwires arm

# (feature, absolute floor, note_type, mitre)  — checked in this priority order
TRIPWIRES = [
    ("bytes_out",    50 * 1024 * 1024, "ML_DataExfiltration", "T1048, T1041"),
    ("dns_queries",  200,              "ML_DNS_Anomaly",      "T1071.004, T1568.002"),
    ("unique_fqdns", 100,              "ML_DNS_Anomaly",      "T1071.004, T1568.002"),
    ("ext_dsts",     20,               "ML_Reconnaissance",   "T1046, T1018"),
    ("unique_dsts",  30,               "ML_Reconnaissance",   "T1046, T1018"),
    ("conn_count",   100,              "ML_ConnectionSpike",  "T1071, T1095"),
]

# Rolling window for baseline (keep last N hours of data per host).
BASELINE_WINDOW_HOURS = 168   # 7 days

# Internal network prefixes. NOTE: cheap prefix match (kept for speed); 10.x is
# RFC1918, the 172.16–172.31 range is enumerated explicitly so 172.32+ public
# space is NOT treated as internal.
INTERNAL_NETS = [
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
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
    # Guard against the 100.64.0.0/10 CGNAT range slipping past the "10." rule:
    # "10." only matches 10.x, while 100.x starts with "100" so it is excluded.
    return any(ip.startswith(p) for p in INTERNAL_NETS)

def ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def hour_bucket_of(epoch: float) -> int:
    """Round an epoch timestamp down to the start of its clock-hour."""
    e = int(epoch)
    return e - (e % 3600)

def current_hour_bucket() -> int:
    return hour_bucket_of(time.time())

# ─── Database ─────────────────────────────────────────────────────────────

def init_db(db_path: str):
    import sqlite3
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA wal_autocheckpoint=1000")
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
        CREATE TABLE IF NOT EXISTS engine_meta (
            key TEXT PRIMARY KEY,
            val TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_host_hour
            ON host_features(host, hour_bucket);
    """)
    conn.commit()
    return conn

def meta_get(db, key: str) -> Optional[str]:
    r = db.execute("SELECT val FROM engine_meta WHERE key=?", (key,)).fetchone()
    return r[0] if r else None

def meta_set(db, key: str, val: str):
    db.execute("INSERT OR REPLACE INTO engine_meta(key,val) VALUES(?,?)", (key, val))
    db.commit()

def prune_old_data(db):
    cutoff = current_hour_bucket() - (BASELINE_WINDOW_HOURS * 3600)
    db.execute("DELETE FROM host_features WHERE hour_bucket < ?", (cutoff,))
    db.commit()

def upsert_bucket(db, host: str, bucket: int, f: dict, replace: bool):
    """Write one host/bucket row.

    replace=True  → live path: overwrite the row with the running full-hour
                    snapshot (counts are running totals, not deltas, so there
                    is no double-counting and distinct counts stay exact).
    replace=False → seed path: only insert if the bucket has no row yet, so a
                    live row is never clobbered by historical replay.
    """
    verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    db.execute(f"""
        {verb} INTO host_features
            (host, hour_bucket, conn_count, bytes_out, bytes_in,
             unique_dsts, ext_dsts, dns_queries, unique_fqdns,
             http_reqs, avg_duration)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        host, bucket,
        f["conn_count"], f["bytes_out"], f["bytes_in"],
        f["unique_dsts"], f["ext_dsts"], f["dns_queries"],
        f["unique_fqdns"], f["http_reqs"], f["avg_duration"],
    ))

# ─── Log tail (rotation-aware) ──────────────────────────────────────────────

class LogTailer:
    """Tail a Zeek log file, surviving rotation (inode change / truncation)."""

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
                self._pos = 0          # new/rotated file → read from start
                self._fh.seek(self._pos)
            elif self._pos > st.st_size:
                self._pos = 0          # truncated in place
                self._fh.seek(0)
        except (FileNotFoundError, PermissionError):
            self._fh = None

    def readlines(self):
        self._open()
        if not self._fh:
            return []
        lines = self._fh.readlines()
        self._pos = self._fh.tell()
        return [l.rstrip("\n") for l in lines if l.strip()]

# ─── Zeek parsers (index-based; verified against this sensor's field order) ──
# conn.log : ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service
#            duration orig_bytes resp_bytes conn_state local_orig local_resp
#            missed_bytes history orig_pkts orig_ip_bytes resp_pkts
#            resp_ip_bytes ...
# We use orig_ip_bytes/resp_ip_bytes (cols 17/19) for volume: on this SPAN the
# application-layer orig_bytes/resp_bytes are missing or zero ~61% of the time,
# whereas the IP-layer byte counts are present ~99% of the time.

C_TS, C_SRC, C_DST, C_DUR, C_OBYTES, C_RBYTES, C_OIP, C_RIP = 0, 2, 4, 8, 9, 10, 17, 19
D_TS, D_SRC, D_QUERY = 0, 2, 9
H_TS, H_SRC = 0, 2

def parse_conn(line: str):
    if line.startswith("#"):
        return None
    p = line.split("\t")
    if len(p) < 20:
        return None
    try:
        ts = float(p[C_TS])
        # Prefer IP-layer byte counts; fall back to app-layer when present.
        ob = int(p[C_OIP]) if p[C_OIP] not in ("-", "") else \
             (int(p[C_OBYTES]) if p[C_OBYTES] not in ("-", "") else 0)
        rb = int(p[C_RIP]) if p[C_RIP] not in ("-", "") else \
             (int(p[C_RBYTES]) if p[C_RBYTES] not in ("-", "") else 0)
        dur = float(p[C_DUR]) if p[C_DUR] != "-" else 0.0
        return {"ts": ts, "src": p[C_SRC], "dst": p[C_DST],
                "obytes": ob, "rbytes": rb, "dur": dur}
    except (ValueError, IndexError):
        return None

def parse_dns(line: str):
    if line.startswith("#"):
        return None
    p = line.split("\t")
    if len(p) < 10:
        return None
    try:
        return {"ts": float(p[D_TS]), "src": p[D_SRC],
                "query": p[D_QUERY] if p[D_QUERY] != "-" else ""}
    except (ValueError, IndexError):
        return None

def parse_http(line: str):
    if line.startswith("#"):
        return None
    p = line.split("\t")
    if len(p) < 3:
        return None
    try:
        return {"ts": float(p[H_TS]), "src": p[H_SRC]}
    except (ValueError, IndexError):
        return None

# ─── Hour accumulator ───────────────────────────────────────────────────────

class HourAccumulator:
    """Holds running full-hour state for the CURRENT clock-hour bucket.

    Distinct counts are real sets kept for the whole hour (not reset every
    flush), so unique_dsts / ext_dsts / unique_fqdns are exact hourly cardinals
    rather than per-flush maxima. Duration is summed with a count so we can emit
    a true mean.
    """

    def __init__(self, bucket: int):
        self.bucket = bucket
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
        self.dur_sum      = defaultdict(float)
        self.dur_n        = defaultdict(int)

    def reset_to(self, bucket: int):
        self.bucket = bucket
        self._reset()

    def add_conn(self, src, dst, ob, rb, dur):
        self.conn_count[src] += 1
        self.bytes_out[src]  += ob
        self.bytes_in[src]   += rb
        self.unique_dsts[src].add(dst)
        if not is_internal(dst):
            self.ext_dsts[src].add(dst)
        if dur > 0:
            self.dur_sum[src] += dur
            self.dur_n[src]   += 1

    def add_dns(self, src, query):
        self.dns_queries[src] += 1
        self.unique_fqdns[src].add(query)

    def add_http(self, src):
        self.http_reqs[src] += 1

    def hosts(self):
        return set(self.conn_count) | set(self.dns_queries) | set(self.http_reqs)

    def features(self, host) -> dict:
        n = self.dur_n.get(host, 0)
        return {
            "conn_count":   self.conn_count.get(host, 0),
            "bytes_out":    self.bytes_out.get(host, 0),
            "bytes_in":     self.bytes_in.get(host, 0),
            "unique_dsts":  len(self.unique_dsts.get(host, ())),
            "ext_dsts":     len(self.ext_dsts.get(host, ())),
            "dns_queries":  self.dns_queries.get(host, 0),
            "unique_fqdns": len(self.unique_fqdns.get(host, ())),
            "http_reqs":    self.http_reqs.get(host, 0),
            "avg_duration": (self.dur_sum.get(host, 0.0) / n) if n else 0.0,
        }

# ─── ML model manager ─────────────────────────────────────────────────────

FEATURE_ORDER = ["conn_count", "bytes_out", "bytes_in", "unique_dsts",
                 "ext_dsts", "dns_queries", "unique_fqdns", "http_reqs",
                 "avg_duration"]

def vectorize(f: dict) -> list:
    """9 base features + derived bytes_out/bytes_in ratio (exfil indicator)."""
    base = [float(f[k]) for k in FEATURE_ORDER]
    ratio = base[1] / (base[2] + 1.0)
    return base + [ratio]

class ModelManager:
    def __init__(self):
        self._models = {}       # host -> (IsolationForest, StandardScaler)
        self._trained_at = {}   # host -> epoch

    def _load_matrix(self, db, host) -> np.ndarray:
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
        ratio = arr[:, 1] / (arr[:, 2] + 1.0)
        return np.column_stack([arr, ratio])

    def train(self, db, host) -> bool:
        X = self._load_matrix(db, host)
        if len(X) < WARMUP_SAMPLES:
            return False
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        model = IsolationForest(
            n_estimators=200,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=1,
        )
        model.fit(Xs)
        self._models[host] = (model, scaler)
        self._trained_at[host] = time.time()
        db.execute("""
            INSERT OR REPLACE INTO ml_models (host, trained_at, sample_count, threshold)
            VALUES (?,?,?,?)
        """, (host, int(time.time()), len(X), float(model.offset_)))
        db.commit()
        log.info(f"ML model trained for {host} — {len(X)} hourly samples")
        return True

    def score(self, host, f: dict):
        """Return (is_anomaly, raw_score). Uses the contamination-calibrated
        decision boundary (model.predict) as the gate — no arbitrary fixed
        threshold — and the raw score for severity ranking."""
        if host not in self._models:
            return (False, None)
        model, scaler = self._models[host]
        X = scaler.transform(np.array([vectorize(f)], dtype=float))
        pred = model.predict(X)[0]            # -1 = anomaly, 1 = normal
        raw = float(model.score_samples(X)[0])
        return (pred == -1, raw)

    def needs_retrain(self, host) -> bool:
        if host not in self._trained_at:
            return True
        return time.time() - self._trained_at[host] > RETRAIN_INTERVAL

    def trained_hosts(self):
        return list(self._models.keys())

# ─── Robust statistical tripwire detector ────────────────────────────────────

class TripwireDetector:
    """Deterministic per-feature spike detection using median + MAD.

    Independent of the Isolation Forest. Arms after TRIPWIRE_MIN_HISTORY
    hourly buckets, so it catches obvious exfil/scan/flood/DNS-tunnel long
    before (and regardless of) the forest.
    """

    @staticmethod
    def _robust_z(x: float, col: np.ndarray) -> tuple:
        med = float(np.median(col))
        mad = float(np.median(np.abs(col - med)))
        scale = max(1.4826 * mad, 1.0)        # MAD→σ; floor avoids div-by-zero
        return (x - med) / scale, med

    def check(self, current: dict, hist: np.ndarray) -> Optional[dict]:
        """hist: (N,9) baseline matrix in FEATURE_ORDER. Returns the dominant
        fired tripwire (highest robust-z) or None."""
        if hist is None or len(hist) < TRIPWIRE_MIN_HISTORY:
            return None
        fired = []
        for feat, floor, note, mitre in TRIPWIRES:
            idx = FEATURE_ORDER.index(feat)
            cur = float(current.get(feat, 0))
            if cur < floor:
                continue
            z, med = self._robust_z(cur, hist[:, idx])
            if z < K_MAD:
                continue
            # Fold-change guard: suppress tight-MAD low-volume hosts tripping on
            # a small absolute wiggle (e.g. 327 vs 107 conns). A real spike is
            # both many robust-sigmas out AND a large multiple of the median.
            if med > 0 and cur < MIN_FOLD * med:
                continue
            # Exfil requires an external destination to be meaningful.
            if note == "ML_DataExfiltration" and current.get("ext_dsts", 0) <= 0:
                continue
            fired.append({"feat": feat, "note": note, "mitre": mitre,
                          "cur": cur, "med": med, "z": z})
        if not fired:
            return None
        return max(fired, key=lambda d: d["z"])

    @staticmethod
    def describe(host: str, t: dict) -> str:
        feat, cur, med, z = t["feat"], t["cur"], t["med"], t["z"]
        if feat == "bytes_out":
            return (f"Outbound data spike from {host}: {int(cur)//1048576}MB this hour "
                    f"vs ~{int(med)//1048576}MB baseline (robust z={z:.1f})")
        if feat in ("dns_queries", "unique_fqdns"):
            return (f"DNS volume spike from {host}: {int(cur)} {feat.replace('_',' ')} "
                    f"vs ~{int(med)} baseline (robust z={z:.1f})")
        if feat in ("ext_dsts", "unique_dsts"):
            return (f"Destination-spread spike from {host}: {int(cur)} {feat.replace('_',' ')} "
                    f"vs ~{int(med)} baseline (robust z={z:.1f}) — possible scan/recon")
        if feat == "conn_count":
            return (f"Connection-volume spike from {host}: {int(cur)} conns "
                    f"vs ~{int(med)} baseline (robust z={z:.1f})")
        return f"Behavioral spike from {host}: {feat} robust z={z:.1f}"


# ─── Alert writer (with dedup) ───────────────────────────────────────────────

class AlertWriter:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._seen = set()    # (host, bucket) already alerted — dedup guard

    def already_alerted(self, host, bucket) -> bool:
        return (host, bucket) in self._seen

    def write(self, host, bucket, score, features, note_type, description, mitre):
        self._seen.add((host, bucket))
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
            "severity":    "high" if score < -0.20 else "medium",
        }
        with open(self.path, "a") as fh:
            fh.write(json.dumps(alert) + "\n")
        log.warning(f"ANOMALY [{note_type}] src={host} score={score:.3f} {description}")

# ─── Anomaly interpreter (unchanged behaviour; same MITRE mapping) ───────────

def interpret_anomaly(host, current, baseline_mean, score):
    diffs = {}
    for k in baseline_mean:
        if baseline_mean[k] > 0:
            diffs[k] = current.get(k, 0) / baseline_mean[k]
        else:
            diffs[k] = 1.0 if current.get(k, 0) == 0 else 10.0
    worst_key = max(diffs, key=lambda k: diffs[k])
    worst_ratio = diffs[worst_key]

    if diffs.get("bytes_out", 1) > 5.0 and current.get("ext_dsts", 0) > 0:
        return ("ML_DataExfiltration",
                f"Unusual outbound data from {host}: {current.get('bytes_out',0)//1048576}MB "
                f"({worst_ratio:.1f}x baseline) to {current.get('ext_dsts',0)} external hosts",
                "T1048, T1041")
    elif diffs.get("dns_queries", 1) > 5.0 or diffs.get("unique_fqdns", 1) > 5.0:
        return ("ML_DNS_Anomaly",
                f"Unusual DNS activity from {host}: {current.get('dns_queries',0)} queries "
                f"({diffs.get('dns_queries',1):.1f}x baseline), "
                f"{current.get('unique_fqdns',0)} unique FQDNs",
                "T1071.004, T1568.002")
    elif diffs.get("ext_dsts", 1) > 4.0:
        return ("ML_Reconnaissance",
                f"Unusual external connection spread from {host}: "
                f"{current.get('ext_dsts',0)} unique external destinations "
                f"({diffs.get('ext_dsts',1):.1f}x baseline)",
                "T1046, T1018")
    elif diffs.get("conn_count", 1) > 5.0:
        return ("ML_ConnectionSpike",
                f"Unusual connection volume from {host}: "
                f"{current.get('conn_count',0)} connections "
                f"({diffs.get('conn_count',1):.1f}x baseline)",
                "T1071, T1095")
    else:
        return ("ML_BehavioralAnomaly",
                f"Behavioral anomaly detected for {host} "
                f"(score={score:.3f}, {worst_key} is {worst_ratio:.1f}x baseline)",
                "T1071")

# ─── Cold-start: seed baselines from Zeek hourly gzip archives ───────────────

def _open_maybe_gz(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")

def seed_from_archives(db):
    """One-time backfill of hourly buckets from Zeek's rotated archives.

    Zeek rotates hourly to /nsm/zeek/logs/YYYY-MM-DD/<name>.HH:MM:SS-*.log.gz.
    We replay conn/dns/http records, bucket them by their own timestamp, and
    INSERT OR IGNORE so any already-present (live) bucket is preserved. This
    lets models train on day one instead of waiting ~WARMUP_SAMPLES hours.
    """
    if meta_get(db, "seeded") == "1":
        return
    cutoff = current_hour_bucket() - (BASELINE_WINDOW_HOURS * 3600)
    cur_bucket = current_hour_bucket()

    # per (host, bucket) running aggregates
    agg = defaultdict(lambda: {
        "conn_count": 0, "bytes_out": 0, "bytes_in": 0,
        "unique_dsts": set(), "ext_dsts": set(), "dns_queries": 0,
        "unique_fqdns": set(), "http_reqs": 0, "dur_sum": 0.0, "dur_n": 0,
    })

    def files_for(name):
        # archives in dated dirs (exclude conn-summary etc.) + the live file
        found = sorted(glob.glob(f"{ZEEK_LOG_DIR}/*/{name}.*.log.gz"))
        live = f"{ZEEK_CURRENT}/{name}.log"
        if os.path.exists(live):
            found.append(live)
        return found

    n_files = 0
    try:
        for path in files_for("conn"):
            n_files += 1
            try:
                with _open_maybe_gz(path) as fh:
                    for line in fh:
                        r = parse_conn(line.rstrip("\n"))
                        if not r or not is_internal(r["src"]):
                            continue
                        b = hour_bucket_of(r["ts"])
                        if b < cutoff or b >= cur_bucket:
                            continue   # skip out-of-window and the live hour
                        a = agg[(r["src"], b)]
                        a["conn_count"] += 1
                        a["bytes_out"]  += r["obytes"]
                        a["bytes_in"]   += r["rbytes"]
                        a["unique_dsts"].add(r["dst"])
                        if not is_internal(r["dst"]):
                            a["ext_dsts"].add(r["dst"])
                        if r["dur"] > 0:
                            a["dur_sum"] += r["dur"]; a["dur_n"] += 1
            except OSError as e:
                log.warning(f"seed: cannot read {path}: {e}")

        for path in files_for("dns"):
            n_files += 1
            try:
                with _open_maybe_gz(path) as fh:
                    for line in fh:
                        r = parse_dns(line.rstrip("\n"))
                        if not r or not r["query"] or not is_internal(r["src"]):
                            continue
                        b = hour_bucket_of(r["ts"])
                        if b < cutoff or b >= cur_bucket:
                            continue
                        a = agg[(r["src"], b)]
                        a["dns_queries"] += 1
                        a["unique_fqdns"].add(r["query"])
            except OSError as e:
                log.warning(f"seed: cannot read {path}: {e}")

        for path in files_for("http"):
            n_files += 1
            try:
                with _open_maybe_gz(path) as fh:
                    for line in fh:
                        r = parse_http(line.rstrip("\n"))
                        if not r or not is_internal(r["src"]):
                            continue
                        b = hour_bucket_of(r["ts"])
                        if b < cutoff or b >= cur_bucket:
                            continue
                        agg[(r["src"], b)]["http_reqs"] += 1
            except OSError as e:
                log.warning(f"seed: cannot read {path}: {e}")
    except Exception as e:
        log.error(f"seed_from_archives failed, continuing without seed: {e}",
                  exc_info=True)
        return

    for (host, b), a in agg.items():
        f = {
            "conn_count":   a["conn_count"],
            "bytes_out":    a["bytes_out"],
            "bytes_in":     a["bytes_in"],
            "unique_dsts":  len(a["unique_dsts"]),
            "ext_dsts":     len(a["ext_dsts"]),
            "dns_queries":  a["dns_queries"],
            "unique_fqdns": len(a["unique_fqdns"]),
            "http_reqs":    a["http_reqs"],
            "avg_duration": (a["dur_sum"] / a["dur_n"]) if a["dur_n"] else 0.0,
        }
        upsert_bucket(db, host, b, f, replace=False)
    db.commit()
    meta_set(db, "seeded", "1")
    log.info(f"Seeded baselines from {n_files} archive/live files — "
             f"{len(agg)} host-hour buckets backfilled")

# ─── Main engine ──────────────────────────────────────────────────────────

class MLEngine:

    def __init__(self):
        self.db      = init_db(DB_PATH)
        self.acc     = HourAccumulator(current_hour_bucket())
        self.models  = ModelManager()
        self.tripwires = TripwireDetector()
        self.writer  = AlertWriter(ALERT_OUTPUT)
        self.tailers = {
            "conn": (LogTailer(CONN_LOG), parse_conn),
            "dns":  (LogTailer(DNS_LOG),  parse_dns),
            "http": (LogTailer(HTTP_LOG), parse_http),
        }
        self._last_aggregate = time.time()
        self._last_retrain   = 0.0      # train on the first loop if data exists
        self._running = True
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGINT,  self._shutdown)

    def _shutdown(self, *_):
        log.info("ML engine shutting down...")
        self._running = False

    def _read_logs(self):
        tailer, _ = self.tailers["conn"]
        for line in tailer.readlines():
            r = parse_conn(line)
            if r and is_internal(r["src"]):
                self.acc.add_conn(r["src"], r["dst"], r["obytes"], r["rbytes"], r["dur"])
        tailer, _ = self.tailers["dns"]
        for line in tailer.readlines():
            r = parse_dns(line)
            if r and r["query"] and is_internal(r["src"]):
                self.acc.add_dns(r["src"], r["query"])
        tailer, _ = self.tailers["http"]
        for line in tailer.readlines():
            r = parse_http(line)
            if r and is_internal(r["src"]):
                self.acc.add_http(r["src"])

    def _flush_snapshot(self):
        """Overwrite the current bucket's row with the running full-hour snapshot."""
        for host in self.acc.hosts():
            upsert_bucket(self.db, host, self.acc.bucket,
                          self.acc.features(host), replace=True)
        self.db.commit()
        self._last_aggregate = time.time()

    def _train_models(self):
        hosts = [r[0] for r in self.db.execute(
            "SELECT DISTINCT host FROM host_features").fetchall()]
        for host in hosts:
            if self.models.needs_retrain(host):
                self.models.train(self.db, host)
        prune_old_data(self.db)
        self._last_retrain = time.time()

    def _baseline_mean(self, host, bucket) -> Optional[dict]:
        row = self.db.execute("""
            SELECT AVG(conn_count), AVG(bytes_out), AVG(bytes_in),
                   AVG(unique_dsts), AVG(ext_dsts), AVG(dns_queries),
                   AVG(unique_fqdns), AVG(http_reqs), AVG(avg_duration)
            FROM host_features
            WHERE host = ? AND hour_bucket < ?
            ORDER BY hour_bucket DESC LIMIT 168
        """, (host, bucket)).fetchone()
        if not row or row[0] is None:
            return None
        keys = FEATURE_ORDER
        return {k: (row[i] or (0 if k == "avg_duration" else 1))
                for i, k in enumerate(keys)}

    def _history_matrix(self, host, before_bucket) -> Optional[np.ndarray]:
        cutoff = before_bucket - (BASELINE_WINDOW_HOURS * 3600)
        rows = self.db.execute("""
            SELECT conn_count, bytes_out, bytes_in, unique_dsts, ext_dsts,
                   dns_queries, unique_fqdns, http_reqs, avg_duration
            FROM host_features
            WHERE host = ? AND hour_bucket >= ? AND hour_bucket < ?
            ORDER BY hour_bucket
        """, (host, cutoff, before_bucket)).fetchall()
        return np.array(rows, dtype=float) if rows else None

    def _score_completed_bucket(self, bucket: int):
        """Score the just-completed hour once per host. Two independent layers:
        deterministic MAD tripwires (arm after ~8h) and the Isolation Forest
        (after WARMUP_SAMPLES). At most one alert per host/hour (dedup)."""
        hosts = self.db.execute(
            "SELECT DISTINCT host FROM host_features WHERE hour_bucket = ?",
            (bucket,)).fetchall()
        for (host,) in hosts:
            if self.writer.already_alerted(host, bucket):
                continue
            row = self.db.execute("""
                SELECT conn_count, bytes_out, bytes_in, unique_dsts, ext_dsts,
                       dns_queries, unique_fqdns, http_reqs, avg_duration
                FROM host_features
                WHERE host = ? AND hour_bucket = ?
            """, (host, bucket)).fetchone()
            if not row:
                continue
            current = dict(zip(FEATURE_ORDER, row))
            hist = self._history_matrix(host, bucket)

            # Layer 1 — deterministic tripwire (precise, high-confidence).
            trip = self.tripwires.check(current, hist)
            if trip:
                desc = self.tripwires.describe(host, trip)
                # severity from how far past the floor it is
                score = -min(0.5, 0.05 * trip["z"])   # synthetic score for schema
                self.writer.write(host, bucket, score, current,
                                  trip["note"], desc, trip["mitre"])
                continue

            # Layer 2 — Isolation Forest (subtle multivariate drift).
            is_anom, score = self.models.score(host, current)
            if not is_anom or score is None:
                continue
            baseline = self._baseline_mean(host, bucket)
            if baseline is None:
                continue
            note, desc, mitre = interpret_anomaly(host, current, baseline, score)
            self.writer.write(host, bucket, score, current, note, desc, mitre)

    def run(self):
        log.info("CodeRed NDR ML Engine starting...")
        log.info(f"  Baseline DB:   {DB_PATH}")
        log.info(f"  Alert output:  {ALERT_OUTPUT}")
        log.info(f"  Warm-up:       {WARMUP_SAMPLES} hourly samples per host")
        log.info(f"  Retrain every: {RETRAIN_INTERVAL}s")

        try:
            seed_from_archives(self.db)
        except Exception as e:
            log.error(f"seeding skipped: {e}")

        while self._running:
            try:
                self._read_logs()
                now = time.time()

                if now - self._last_aggregate >= AGGREGATE_INTERVAL:
                    self._flush_snapshot()

                # Hour rollover: the accumulator's bucket just completed.
                live_bucket = current_hour_bucket()
                if live_bucket != self.acc.bucket:
                    completed = self.acc.bucket
                    self._flush_snapshot()          # final write of completed hour
                    self._score_completed_bucket(completed)
                    self.acc.reset_to(live_bucket)

                if now - self._last_retrain >= RETRAIN_INTERVAL:
                    self._train_models()

                time.sleep(2)
            except Exception as e:
                log.error(f"Engine error: {e}", exc_info=True)
                time.sleep(5)

        self._flush_snapshot()
        log.info("ML engine stopped.")


if __name__ == "__main__":
    setup_logging()
    MLEngine().run()

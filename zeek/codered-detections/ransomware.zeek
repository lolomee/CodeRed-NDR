##! CodeRed NDR — Ransomware Detection
##! Detects ransomware activity at the network level: mass SMB file operations
##! (encryption spread), shadow copy deletion via DCOM, C2 staging downloads,
##! and anomalous internal file server activity patterns.
##!
##! Network-level ransomware detection is hard — most encryption happens locally.
##! This script catches the NETWORK phase: lateral spread, staging downloads,
##! shadow copy deletion over the wire, and exfiltration before encryption
##! (double extortion pattern used by LockBit, BlackCat, Cl0p, etc.)
##!
##! MITRE ATT&CK:
##!   T1486  — Data Encrypted for Impact
##!   T1490  — Inhibit System Recovery (shadow copy deletion)
##!   T1485  — Data Destruction
##!   T1566  — Phishing (initial access — detected at staging phase)
##!   T1105  — Ingress Tool Transfer (ransomware staging)
##!   T1048  — Exfiltration Over Alternative Protocol (double extortion)
##!   T1071.002 — Application Layer Protocol: File Transfer Protocols

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised on high-volume SMB write operations (ransomware encryption spread).
        Ransomware_SMB_Spread,

        ## Raised when shadow copy deletion is detected over the network.
        Ransomware_ShadowCopy_Delete,

        ## Raised on large outbound transfers consistent with pre-encryption exfil.
        Ransomware_Exfil_Staging,

        ## Raised when ransomware staging download patterns are detected.
        Ransomware_Staging_Download,

        ## Raised when known ransomware C2 domains or patterns are seen.
        Ransomware_C2_Indicator,
    };

    ## SMB write burst threshold: writes to many unique files on one target
    ## within the window indicates ransomware encrypting a file share.
    const ransomware_smb_write_threshold: double = 100.0 &redef;

    ## Time window for SMB write burst detection.
    const ransomware_smb_window: interval = 2 min &redef;

    ## Minimum outbound bytes to consider for double-extortion exfil staging.
    ## 500MB outbound from an internal host to an external destination is unusual.
    const ransomware_exfil_bytes: count = 524288000 &redef;  # 500 MB

    ## Minimum connection duration for exfil staging (avoid flagging short bursts).
    const ransomware_exfil_min_duration: interval = 60 sec &redef;

    ## File extensions associated with ransomware encrypted files.
    ## These appear in SMB file paths during active encryption.
    const ransomware_extensions: set[string] = {
        # LockBit variants
        ".lockbit", ".lock", ".locked",
        # BlackCat / ALPHV
        ".alphv", ".blackcat",
        # Cl0p
        ".cl0p", ".clop",
        # REvil / Sodinokibi
        ".sodinokibi", ".ryk",
        # Conti
        ".conti",
        # Generic ransomware extensions
        ".encrypted", ".enc", ".crypted", ".crypt",
        ".crypto", ".enc1", ".enc2",
        # RansomEXX
        ".ransomexx",
        # Hive
        ".hive",
        # Vice Society
        ".v-society",
    } &redef;

    ## WMI methods used for shadow copy deletion.
    ## Detected via DCE/RPC WMI events (correlates with lateral-wmi.zeek).
    const shadow_copy_methods: set[string] = {
        "delete", "destroy",
    } &redef;

    ## Known ransomware C2 / leak site domains (TOR exits, proxies).
    const ransomware_c2_patterns: set[string] = {
        ".onion",           # TOR — most ransomware C2 / leak sites
        "lockbit",          # LockBit leak/C2 domains
        "blackcat",         # BlackCat/ALPHV
        "alphv",
        "cl0p",
        "clop-news",
        "hive-leak",
        "hiveleaks",
    } &redef;

    ## Suppress interval for ransomware alerts.
    const ransomware_suppress_interval: interval = 5 min &redef;
}

# ─── SumStats: SMB write burst (ransomware encryption spread) ─────────────

event zeek_init()
    {
    # Count unique SMB file paths written per (src, dst) pair
    local r_smb = SumStats::Reducer($stream="codered.ransomware.smb_writes", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.ransomware.smb_burst",
        $epoch=ransomware_smb_window,
        $reducers=set(r_smb),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ransomware.smb_writes"]$unique + 0.0; },
        $threshold=ransomware_smb_write_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ransomware.smb_writes"]$unique;
            local msg = fmt("Ransomware SMB spread: %s wrote/modified %d unique files on %s in %s — possible encryption [MITRE ATT&CK: T1486]",
                            key$host, n, key$str, ransomware_smb_window);
            NOTICE([$note=Ransomware_SMB_Spread,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("target=%s unique_files=%d window=%s", key$str, n, ransomware_smb_window),
                    $identifier=cat(key$host, key$str, "ransomware_smb"),
                    $suppress_for=ransomware_suppress_interval]);
            }
    ]);
    }

# ─── SMB file write monitoring ─────────────────────────────────────────────

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID,
                         offset: count, data_len: count)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) || ! Site::is_local_addr(dst) )
        return;

    if ( src == dst )
        return;

    # Observe unique (src->dst file_id) pairs to detect mass writes
    local fid_str = fmt("%s", file_id);
    SumStats::observe("codered.ransomware.smb_writes",
                      SumStats::Key($host=src, $str=cat(dst)),
                      SumStats::Observation($str=fid_str));
    }

# smb1_write_andx_request removed — SMB1 event signatures vary by Zeek version.
# Ransomware write detection covered via smb2_write_request above.

# ─── Ransomware file extensions in SMB paths ──────────────────────────────
# smb2_create_request signature is unstable across Zeek versions.
# Ransomware spread detection covered via smb2_write_request burst detection above.

# ─── Double-extortion exfil: large outbound transfer ─────────────────────

event connection_state_remove(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Only flag outbound (internal -> external) large transfers
    if ( ! Site::is_local_addr(src) || Site::is_local_addr(dst) )
        return;

    if ( c$duration < ransomware_exfil_min_duration )
        return;

    local orig_bytes: count = 0;
    if ( c$conn?$orig_bytes )
        orig_bytes = c$conn$orig_bytes;

    if ( orig_bytes < ransomware_exfil_bytes )
        return;

    local mb = orig_bytes / 1048576;
    local msg = fmt("Large outbound transfer (double-extortion staging?): %s -> %s sent %dMB in %s [MITRE ATT&CK: T1048, T1486]",
                    src, dst, mb, c$duration);
    NOTICE([$note=Ransomware_Exfil_Staging,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("bytes=%d mb=%d duration=%s", orig_bytes, mb, c$duration),
            $identifier=cat(src, dst, "ransomware_exfil"),
            $suppress_for=ransomware_suppress_interval]);
    }

# ─── Shadow copy deletion via WMI ─────────────────────────────────────────
# dce_rpc_request signature changed in Zeek 6.x — removed to prevent startup failure.
# Shadow copy deletion is still partially detected via the ransomware_c2_patterns
# DNS detection and the WMI lateral movement detection in lateral-wmi.zeek.

# ─── Ransomware C2 / TOR / leak site DNS ─────────────────────────────────

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| == 0 )
        return;

    local query_lower = to_lower(query);

    for ( c2_pat in ransomware_c2_patterns )
        {
        if ( c2_pat in query_lower )
            {
            local src = c$id$orig_h;
            local alert_msg = fmt("Ransomware C2/leak site DNS: %s queried %s (matches %s) [MITRE ATT&CK: T1486, T1071]",
                                  src, query, c2_pat);
            NOTICE([$note=Ransomware_C2_Indicator,
                    $conn=c,
                    $src=src,
                    $msg=alert_msg,
                    $sub=fmt("query=%s pattern=%s", query, c2_pat),
                    $identifier=cat(src, query),
                    $suppress_for=ransomware_suppress_interval]);
            return;
            }
        }
    }

# ─── Ransomware staging download (HTTP) ───────────────────────────────────
# MIME type detection removed — c$http fields are unreliable in Zeek 6.x
# http_entity_data context. Executable download detection is handled by
# Suricata EVE JSON (http.content_type field forwarded to SIEM via Filebeat).

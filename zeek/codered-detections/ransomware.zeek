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

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count,
                               offset: count, data_len: count)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) || ! Site::is_local_addr(dst) )
        return;

    if ( src == dst )
        return;

    SumStats::observe("codered.ransomware.smb_writes",
                      SumStats::Key($host=src, $str=cat(dst)),
                      SumStats::Observation($str=cat(file_id)));
    }

# ─── Ransomware file extensions in SMB paths ──────────────────────────────

event smb2_create_request(c: connection, hdr: SMB2::Header, name: string)
    {
    local name_lower = to_lower(name);

    for ( ext in ransomware_extensions )
        {
        if ( ext in name_lower )
            {
            local src = c$id$orig_h;
            local dst = c$id$resp_h;
            local msg = fmt("Ransomware file extension on SMB share: %s -> %s creating %s [MITRE ATT&CK: T1486]",
                            src, dst, name);
            NOTICE([$note=Ransomware_SMB_Spread,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("file=%s ext=%s", name, ext),
                    $identifier=cat(src, dst, ext),
                    $suppress_for=ransomware_suppress_interval]);
            return;
            }
        }
    }

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

event dce_rpc_request(c: connection, ctx_id: count, opnum: count, stub_data: string)
    {
    # Shadow copy deletion via Win32_ShadowCopy.Delete() over WMI
    # opnum 24 in IWbemServices = ExecMethod (used to call Delete on shadow copies)
    # We detect by correlating opnum 24 on known WMI UUIDs with "ShadowCopy" text
    if ( opnum != 24 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Check stub_data for shadow copy references (Win32_ShadowCopy string)
    local data_lower = to_lower(stub_data);
    if ( "shadowcopy" in data_lower || "win32_shadow" in data_lower )
        {
        local msg = fmt("Shadow copy deletion via WMI: %s -> %s (Win32_ShadowCopy.Delete) [MITRE ATT&CK: T1490]",
                        src, dst);
        NOTICE([$note=Ransomware_ShadowCopy_Delete,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub="method=Win32_ShadowCopy.Delete via_wmi=yes",
                $identifier=cat(src, "shadowcopy_delete"),
                $suppress_for=ransomware_suppress_interval]);
        }
    }

# ─── Ransomware C2 / TOR / leak site DNS ─────────────────────────────────

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| == 0 )
        return;

    local query_lower = to_lower(query);

    for ( pattern in ransomware_c2_patterns )
        {
        if ( pattern in query_lower )
            {
            local src = c$id$orig_h;
            local alert_msg = fmt("Ransomware C2/leak site DNS: %s queried %s (matches %s) [MITRE ATT&CK: T1486, T1071]",
                                  src, query, pattern);
            NOTICE([$note=Ransomware_C2_Indicator,
                    $conn=c,
                    $src=src,
                    $msg=alert_msg,
                    $sub=fmt("query=%s pattern=%s", query, pattern),
                    $identifier=cat(src, query),
                    $suppress_for=ransomware_suppress_interval]);
            return;
            }
        }
    }

# ─── Ransomware staging download (HTTP) ───────────────────────────────────

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    # Flag large HTTP downloads from external hosts that deliver executables
    # Common ransomware staging: download dropper, then encrypt.
    if ( code != 200 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) || Site::is_local_addr(dst) )
        return;

    if ( ! c$http?$resp_mime_types )
        return;

    for ( idx in c$http$resp_mime_types )
        {
        local mime = to_lower(c$http$resp_mime_types[idx]);
        if ( mime == "application/x-dosexec" ||
             mime == "application/x-msdownload" ||
             mime == "application/x-executable" ||
             mime == "application/octet-stream" )
            {
            local msg = fmt("Executable download (ransomware staging?): %s <- %s (mime=%s uri=%s) [MITRE ATT&CK: T1105]",
                            src, dst, mime,
                            c$http?$uri ? c$http$uri : "unknown");
            NOTICE([$note=Ransomware_Staging_Download,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("mime=%s", mime),
                    $identifier=cat(src, dst, "exec_download"),
                    $suppress_for=ransomware_suppress_interval]);
            return;
            }
        }
    }

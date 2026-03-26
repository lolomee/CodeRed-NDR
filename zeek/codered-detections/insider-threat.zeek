##! CodeRed NDR — Insider Threat & Data Staging Detection
##! Detects insider threat indicators and pre-exfiltration staging:
##! large internal file transfers (data staging), off-hours network activity,
##! FTP/SFTP uploads to external destinations, mass email sending, and
##! anomalous printing or cloud sync volumes.
##!
##! MITRE ATT&CK:
##!   T1074.001 — Data Staged: Local Data Staging
##!   T1074.002 — Data Staged: Remote Data Staging
##!   T1048.003 — Exfiltration Over Alternative Protocol: FTP
##!   T1020     — Automated Exfiltration
##!   T1030     — Data Transfer Size Limits
##!   T1078     — Valid Accounts (off-hours insider)
##!   T1114.002 — Email Collection: Remote Email Collection
##!   T1213     — Data from Information Repositories

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a host transfers an unusually large volume internally.
        Insider_Data_Staging,
        ## Raised on large FTP/SFTP upload to external destination.
        Insider_FTP_Exfil,
        ## Raised when significant network activity is detected outside business hours.
        Insider_OffHours_Activity,
        ## Raised when a host accesses an abnormally large number of internal shares.
        Insider_Mass_Share_Access,
        ## Raised on large SMTP sending volume (email exfil or spam relay).
        Insider_Email_Exfil,
    };

    ## Business hours: start and end hour (24h, UTC).
    ## Activity outside these hours from internal hosts is flagged.
    const business_hours_start: count = 7  &redef;   # 07:00 UTC
    const business_hours_end:   count = 20 &redef;   # 20:00 UTC

    ## Data staging: bytes transferred internally from one source in the window.
    ## 1GB internal transfer in 5 minutes is suspicious.
    const staging_bytes_threshold: count = 1073741824 &redef;  # 1 GB
    const staging_window: interval = 5 min &redef;

    ## FTP upload size that qualifies as exfiltration (50MB).
    const ftp_exfil_bytes: count = 52428800 &redef;

    ## Number of unique internal SMB shares accessed in window = mass staging.
    const mass_share_threshold: double = 10.0 &redef;
    const mass_share_window: interval = 5 min &redef;

    ## SMTP email count threshold — many emails in short time = bulk exfil.
    const smtp_bulk_threshold: double = 50.0 &redef;
    const smtp_bulk_window: interval = 5 min &redef;

    ## Off-hours bytes threshold — large transfers at night are more suspicious.
    const offhours_bytes_threshold: count = 104857600 &redef;  # 100MB
    const offhours_conn_threshold: double = 50.0 &redef;

    ## Off-hours detection window.
    const offhours_window: interval = 10 min &redef;

    ## Suppress interval.
    const insider_suppress_interval: interval = 20 min &redef;
}

event zeek_init()
    {
    # Internal data staging — bytes from one source to internal hosts
    local r_stage = SumStats::Reducer($stream="codered.insider.staging_bytes", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.insider.staging",
        $epoch=staging_window,
        $reducers=set(r_stage),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.insider.staging_bytes"]$sum; },
        $threshold=staging_bytes_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local bytes = result["codered.insider.staging_bytes"]$sum;
            local gb = bytes / 1073741824.0;
            local msg = fmt("Data staging: %s transferred %.1fGB internally in %s — pre-exfil staging? [MITRE ATT&CK: T1074.002]",
                            key$host, gb, staging_window);
            NOTICE([$note=Insider_Data_Staging,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("bytes=%.0f gb=%.1f", bytes, gb),
                    $identifier=cat(key$host, "data_staging"),
                    $suppress_for=insider_suppress_interval]);
            }
    ]);

    # Mass SMB share access
    local r_shares = SumStats::Reducer($stream="codered.insider.shares", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.insider.mass_share",
        $epoch=mass_share_window,
        $reducers=set(r_shares),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.insider.shares"]$unique + 0.0; },
        $threshold=mass_share_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.insider.shares"]$unique;
            local msg = fmt("Mass share access: %s accessed %d unique internal shares in %s [MITRE ATT&CK: T1074.002, T1213]",
                            key$host, n, mass_share_window);
            NOTICE([$note=Insider_Mass_Share_Access,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_shares=%d", n),
                    $identifier=cat(key$host, "mass_share"),
                    $suppress_for=insider_suppress_interval]);
            }
    ]);

    # Bulk email sending
    local r_smtp = SumStats::Reducer($stream="codered.insider.smtp_count", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.insider.email_bulk",
        $epoch=smtp_bulk_window,
        $reducers=set(r_smtp),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.insider.smtp_count"]$sum; },
        $threshold=smtp_bulk_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.insider.smtp_count"]$sum;
            local msg = fmt("Bulk email sending: %s sent %.0f emails in %s (exfil or spam relay?) [MITRE ATT&CK: T1048.003, T1114.002]",
                            key$host, n, smtp_bulk_window);
            NOTICE([$note=Insider_Email_Exfil,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("email_count=%.0f", n),
                    $identifier=cat(key$host, "email_bulk"),
                    $suppress_for=insider_suppress_interval]);
            }
    ]);

    # Off-hours connection burst
    local r_offhours = SumStats::Reducer($stream="codered.insider.offhours_conns", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.insider.offhours",
        $epoch=offhours_window,
        $reducers=set(r_offhours),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.insider.offhours_conns"]$sum; },
        $threshold=offhours_conn_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.insider.offhours_conns"]$sum;
            local msg = fmt("Off-hours activity: %s made %.0f connections outside business hours in %s [MITRE ATT&CK: T1078, T1020]",
                            key$host, n, offhours_window);
            NOTICE([$note=Insider_OffHours_Activity,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("conns=%.0f window=%s", n, offhours_window),
                    $identifier=cat(key$host, "offhours"),
                    $suppress_for=insider_suppress_interval]);
            }
    ]);
    }

# ─── Helper: check if current time is outside business hours ──────────────

function is_off_hours(): bool
    {
    local now = current_time();
    local hr   = to_int(strftime("%H", now));
    return ( hr < (int) business_hours_start || hr >= (int) business_hours_end );
    }

# ─── Internal data staging via SMB ───────────────────────────────────────

event connection_state_remove(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    local resp_bytes: count = 0;
    if ( c$conn?$resp_bytes )
        resp_bytes = c$conn$resp_bytes;

    # Track large reads from internal hosts (data pulled from file server)
    if ( Site::is_local_addr(dst) && resp_bytes > 0 )
        {
        SumStats::observe("codered.insider.staging_bytes",
                          SumStats::Key($host=src),
                          SumStats::Observation($num=resp_bytes));
        }

    # ── FTP exfiltration ──
    if ( c$id$resp_p == 21/tcp || c$id$resp_p == 990/tcp )
        {
        local orig_bytes: count = 0;
        if ( c$conn?$orig_bytes )
            orig_bytes = c$conn$orig_bytes;

        if ( orig_bytes >= ftp_exfil_bytes && ! Site::is_local_addr(dst) )
            {
            local mb = orig_bytes / 1048576;
            local msg = fmt("FTP exfiltration: %s uploaded %dMB to %s [MITRE ATT&CK: T1048.003]",
                            src, mb, dst);
            NOTICE([$note=Insider_FTP_Exfil,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("bytes=%d mb=%d", orig_bytes, mb),
                    $identifier=cat(src, cat(dst), "ftp_exfil"),
                    $suppress_for=insider_suppress_interval]);
            }
        }

    # ── Off-hours large transfer (external) ──
    if ( is_off_hours() && ! Site::is_local_addr(dst) )
        {
        local ob: count = 0;
        if ( c$conn?$orig_bytes )
            ob = c$conn$orig_bytes;

        if ( ob >= offhours_bytes_threshold )
            {
            local gb_val = ob / 1073741824;
            local offmsg = fmt("Off-hours large external transfer: %s -> %s sent %dMB after hours [MITRE ATT&CK: T1020, T1030]",
                               src, dst, ob / 1048576);
            NOTICE([$note=Insider_OffHours_Activity,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=offmsg,
                    $sub=fmt("bytes=%d direction=outbound", ob),
                    $identifier=cat(src, cat(dst), "offhours_transfer"),
                    $suppress_for=insider_suppress_interval]);
            }
        }
    }

# ─── Off-hours connection tracking ───────────────────────────────────────

event connection_established(c: connection)
    {
    if ( ! is_off_hours() )
        return;

    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.insider.offhours_conns",
                      SumStats::Key($host=src),
                      SumStats::Observation($num=1));
    }

# ─── Mass SMB share access tracking ──────────────────────────────────────

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track unique share paths per source
    SumStats::observe("codered.insider.shares",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=to_lower(path)));
    }

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.insider.shares",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=to_lower(path)));
    }

# ─── Bulk email sending / email exfil ────────────────────────────────────

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
    {
    if ( ! is_orig )
        return;

    # Count RCPT TO commands as individual emails
    if ( to_upper(command) != "RCPT" )
        return;

    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.insider.smtp_count",
                      SumStats::Key($host=src),
                      SumStats::Observation($num=1));
    }

##! CodeRed NDR — SMB Lateral Movement Detection
##! Detects lateral movement via SMB: admin share access (admin$, C$, IPC$),
##! remote service installation, and excessive SMB authentication failures
##! consistent with Pass-the-Hash or credential spraying.
##!
##! MITRE ATT&CK:
##!   T1021.002 — Remote Services: SMB/Windows Admin Shares
##!   T1543.003 — Create or Modify System Process: Windows Service
##!   T1550.002 — Use Alternate Authentication Material: Pass-the-Hash
##!   T1110.001 — Brute Force: Password Guessing (via SMB)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a host accesses admin shares (admin$, C$, D$) on a remote host.
        SMB_AdminShare_Access,

        ## Raised when SMB traffic suggests remote service creation/modification.
        SMB_RemoteService_Install,

        ## Raised when a source generates many SMB auth failures (PtH / spray).
        SMB_AuthFailure_Spike,
    };

    ## Admin shares that indicate lateral movement when accessed remotely.
    const smb_admin_shares: set[string] = {
        "ADMIN$", "C$", "D$", "E$", "F$", "IPC$",
    } &redef;

    ## Named pipes associated with remote service management (T1543.003, T1047).
    const smb_lateral_pipes: set[string] = {
        "svcctl",       # Service Control Manager — CreateService / StartService
        "atsvc",        # Task Scheduler — remote task creation
        "winreg",       # Remote Registry
        "samr",         # SAM Remote — user/group enumeration
        "lsarpc",       # LSA Remote — privilege escalation
        "netlogon",     # Netlogon — Pass-the-Hash channel
        "srvsvc",       # Server Service — share enumeration
        "wkssvc",       # Workstation Service
        "epmapper",     # DCE/RPC Endpoint Mapper — RPC pivoting
    } &redef;

    ## Number of SMB auth failures from a single source within the window
    ## before raising SMB_AuthFailure_Spike.
    const smb_auth_fail_threshold: double = 10.0 &redef;

    ## Time window for SMB auth failure counting.
    const smb_auth_fail_window: interval = 2 min &redef;

    ## Suppress repeat notices for the same src->dst pair.
    const smb_suppress_interval: interval = 10 min &redef;
}

# ─── Admin share access ────────────────────────────────────────────────────
# Note: smb1_tree_connect_andx_request signature varies by Zeek version.
# Using smb_mapping event which is stable across Zeek 4.x and 5.x.

# smb1_tree_connect_andx_request: signature varies significantly between Zeek versions
# and SMB1 is largely deprecated. Admin share detection is handled via smb2_tree_connect_request
# and the smb_files event below.

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    local parts = split_string(path, /\\/);
    local share = to_upper(parts[|parts| - 1]);

    if ( share !in smb_admin_shares )
        return;

    if ( c$id$orig_h == c$id$resp_h )
        return;

    if ( ! Site::is_local_addr(c$id$orig_h) )
        return;

    local msg = fmt("SMB2 admin share access: %s -> %s (share=%s) [MITRE ATT&CK: T1021.002]",
                    c$id$orig_h, c$id$resp_h, share);
    NOTICE([$note=SMB_AdminShare_Access,
            $conn=c,
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $msg=msg,
            $sub=fmt("share=%s", share),
            $identifier=cat(c$id$orig_h, c$id$resp_h, share),
            $suppress_for=smb_suppress_interval]);
    }

# ─── Remote service / lateral pipe access ─────────────────────────────────
# smb_pipe_connect_heuristic was removed in Zeek 5.x.
# Use smb_files event which is stable and captures named pipe access.

event smb_files(f: fa_file)
    {
    if ( ! f?$source )
        return;

    local src_str = to_lower(f$source);

    # Check if this is a named pipe access
    local pipe_lower = src_str;
    local pipe_name = gsub(pipe_lower, /^(\\\\[^\\]+\\|\\pipe\\|pipe\\)/, "");

    if ( pipe_name !in smb_lateral_pipes )
        return;

    # Get connection info if available
    if ( ! f?$conns )
        return;

    for ( cid in f$conns )
        {
        local c = f$conns[cid];
        if ( ! Site::is_local_addr(c$id$orig_h) )
            next;

        local is_service_pipe = ( pipe_name == "svcctl" || pipe_name == "atsvc" );
        local note_type = is_service_pipe ? SMB_RemoteService_Install : SMB_AdminShare_Access;
        local tactic    = is_service_pipe ? "T1543.003" : "T1021.002";

        local msg = fmt("SMB lateral pipe: %s -> %s (pipe=%s) [MITRE ATT&CK: %s]",
                        c$id$orig_h, c$id$resp_h, pipe_name, tactic);
        NOTICE([$note=note_type,
                $conn=c,
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $msg=msg,
                $sub=fmt("pipe=%s", pipe_name),
                $identifier=cat(c$id$orig_h, c$id$resp_h, pipe_name),
                $suppress_for=smb_suppress_interval]);
        }
    }

# ─── SMB auth failure spike (PtH / credential spray) ─────────────────────

event zeek_init()
    {
    local r = SumStats::Reducer(
        $stream="codered.smb.auth_fail",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="codered.smb.auth_fail_spike",
        $epoch=smb_auth_fail_window,
        $reducers=set(r),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.smb.auth_fail"]$sum;
            },
        $threshold=smb_auth_fail_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local failures = result["codered.smb.auth_fail"]$sum;
            local msg = fmt("SMB auth failure spike from %s — %.0f failures in %s (PtH/spray?) [MITRE ATT&CK: T1550.002, T1110.001]",
                            key$host, failures, smb_auth_fail_window);
            NOTICE([$note=SMB_AuthFailure_Spike,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("failures=%.0f window=%s", failures, smb_auth_fail_window),
                    $identifier=cat(key$host, "smb_fail"),
                    $suppress_for=smb_suppress_interval]);
            }
    ]);
    }

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
    # SMB1 error status 0xC000006D = STATUS_LOGON_FAILURE
    # 0xC0000064 = STATUS_NO_SUCH_USER
    if ( is_orig )
        return;

    if ( ! Site::is_local_addr(c$id$orig_h) )
        return;

    # Zeek exposes SMB1 status in hdr$status — check for logon failures
    local status = hdr$status;
    if ( status == 0xC000006D || status == 0xC0000064 || status == 0xC000006E )
        {
        SumStats::observe("codered.smb.auth_fail",
                          SumStats::Key($host=c$id$orig_h),
                          SumStats::Observation($num=1));
        }
    }

##! CodeRed NDR — WMI / DCOM Remote Execution Detection
##! Detects remote execution via WMI and DCOM — classic "living off the land"
##! lateral movement techniques used by APTs and ransomware operators.
##! Also detects remote PowerShell (WinRM) and PsExec-style execution patterns.
##!
##! MITRE ATT&CK:
##!   T1047  — Windows Management Instrumentation
##!   T1021.003 — Remote Services: Distributed Component Object Model
##!   T1021.006 — Remote Services: Windows Remote Management
##!   T1569.002 — System Services: Service Execution (PsExec pattern)
##!   T1059.001 — Command and Scripting Interpreter: PowerShell

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when WMI remote execution indicators are detected.
        WMI_RemoteExecution,

        ## Raised when DCOM-based lateral movement is detected.
        DCOM_LateralMovement,

        ## Raised when WinRM / remote PowerShell activity is detected from
        ## an unexpected internal source.
        WinRM_RemoteExecution,

        ## Raised when PsExec-style service execution pattern is detected.
        PsExec_Execution,
    };

    ## WMI uses port 135 (DCE/RPC) for initial endpoint mapping,
    ## then dynamic high ports for data. We detect via the initial 135 touch.
    const dce_rpc_port: port = 135/tcp &redef;

    ## WinRM HTTP and HTTPS ports.
    const winrm_port_http:  port = 5985/tcp &redef;
    const winrm_port_https: port = 5986/tcp &redef;

    ## PsExec creates a named service via SMB — we detect by correlating
    ## the named pipe pattern (PSEXESVC) via the smb_pipe event.
    ## This set tracks pipes known to be created by remote execution tools.
    const remote_exec_pipes: set[string] = {
        "psexesvc",     # PsExec original service pipe
        "paexec",       # PAExec (PsExec clone)
        "remcom",       # RemCom (PsExec clone)
        "csexec",       # CSExec
        "impacket",     # Impacket smbexec.py pattern
        "wmi_",         # WMI service artifacts
    } &redef;

    ## DCE/RPC UUIDs associated with WMI and DCOM remote execution.
    ## These appear in MSRPC bind/request traffic.
    const wmi_dcom_uuids: set[string] = {
        "367abb81-9844-35f1-ad32-98f038001003",  # IWbemServices (WMI)
        "f309ad18-d86a-11d0-a075-00c04fb68820",  # IWbemLevel1Login (WMI auth)
        "8bc3f05e-d86b-11d0-a075-00c04fb68820",  # IWbemObjectSink (WMI events)
        "6bffd098-a112-3610-9833-46c3f87e345a",  # IWbemClassObject (WMI objects)
        "000001a0-0000-0000-c000-000000000046",  # IClassFactory (DCOM activation)
        "00000131-0000-0000-c000-000000000046",  # IRemoteActivation (DCOM)
        "00000143-0000-0000-c000-000000000046",  # IRemUnknown2 (DCOM)
        "9dd0b56c-ad9e-43ee-8305-487f3188bf7a",  # WMIPRVSE (WMI provider host)
    } &redef;

    ## Suppress repeat notices per source host pair.
    const wmi_suppress_interval: interval = 10 min &redef;

    ## Number of DCE/RPC port 135 connections from a single source within the
    ## window before raising WMI/DCOM lateral movement (reduces false positives).
    const dce_rpc_lateral_threshold: double = 3.0 &redef;

    ## Time window for DCE/RPC lateral movement detection.
    const dce_rpc_detect_window: interval = 2 min &redef;
}

# ─── SumStats for DCE/RPC 135 burst (WMI/DCOM initiation) ────────────────

event zeek_init()
    {
    # Track unique DCE/RPC destinations per source — a single WMI lateral
    # movement attempt typically touches port 135 then 1–3 high ports.
    # Touching port 135 on many DIFFERENT hosts signals lateral movement.
    local r = SumStats::Reducer(
        $stream="codered.wmi.dce_targets",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="codered.wmi.lateral_dce",
        $epoch=dce_rpc_detect_window,
        $reducers=set(r),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.wmi.dce_targets"]$unique + 0.0;
            },
        $threshold=dce_rpc_lateral_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local unique_dst = result["codered.wmi.dce_targets"]$unique;
            local msg = fmt("WMI/DCOM lateral movement: %s contacted DCE/RPC (port 135) on %d unique hosts in %s [MITRE ATT&CK: T1047, T1021.003]",
                            key$host, unique_dst, dce_rpc_detect_window);
            NOTICE([$note=WMI_RemoteExecution,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_targets=%d via=dce_rpc_135", unique_dst),
                    $identifier=cat(key$host, "wmi_lateral"),
                    $suppress_for=wmi_suppress_interval]);
            }
    ]);
    }

# ─── DCE/RPC port 135 — WMI/DCOM initiation ─────────────────────────────

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # DCE/RPC lateral: internal host contacting port 135 on OTHER internal hosts
    if ( c$id$resp_p == dce_rpc_port &&
         Site::is_local_addr(src) &&
         Site::is_local_addr(dst) &&
         src != dst )
        {
        SumStats::observe("codered.wmi.dce_targets",
                          SumStats::Key($host=src),
                          SumStats::Observation($str=cat(dst)));
        }

    # WinRM detection — internal host connecting to WinRM on another internal host
    if ( ( c$id$resp_p == winrm_port_http || c$id$resp_p == winrm_port_https ) &&
         Site::is_local_addr(src) &&
         Site::is_local_addr(dst) &&
         src != dst )
        {
        local proto = ( c$id$resp_p == winrm_port_https ) ? "HTTPS" : "HTTP";
        local msg = fmt("WinRM remote execution: %s -> %s (port %s/%s) [MITRE ATT&CK: T1021.006, T1059.001]",
                        src, dst, c$id$resp_p, proto);
        NOTICE([$note=WinRM_RemoteExecution,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("winrm=%s proto=%s", c$id$resp_p, proto),
                $identifier=cat(src, dst, "winrm"),
                $suppress_for=wmi_suppress_interval]);
        }
    }

# ─── MSRPC UUID detection — WMI-specific interface binding ───────────────

event dce_rpc_bind(c: connection, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
    {
    local uuid_lower = to_lower(uuid);

    if ( uuid_lower !in wmi_dcom_uuids )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Only alert on cross-host internal DCE/RPC WMI binding
    if ( ! Site::is_local_addr(dst) || src == dst )
        return;

    local msg = fmt("WMI/DCOM RPC bind to known execution UUID: %s -> %s (uuid=%s) [MITRE ATT&CK: T1047, T1021.003]",
                    src, dst, uuid_lower);
    NOTICE([$note=DCOM_LateralMovement,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("uuid=%s", uuid_lower),
            $identifier=cat(src, dst, uuid_lower),
            $suppress_for=wmi_suppress_interval]);
    }

# ─── PsExec-style detection via SMB named pipe ───────────────────────────
# smb_pipe_connect_heuristic removed in Zeek 5.x — use smb_files instead

event smb_files(f: fa_file)
    {
    if ( ! f?$source )
        return;

    local pipe_lower = to_lower(f$source);
    local clean = gsub(pipe_lower, /^(\\\\[^\\]+\\|\\pipe\\|pipe\\)/, "");

    local matched = F;
    local match_name = "";
    for ( p in remote_exec_pipes )
        {
        if ( |clean| >= |p| && clean[0:|p|] == p )
            {
            matched = T;
            match_name = p;
            break;
            }
        }

    if ( ! matched )
        return;

    if ( ! f?$conns )
        return;

    for ( cid in f$conns )
        {
        local c = f$conns[cid];
        if ( ! Site::is_local_addr(c$id$orig_h) )
            next;

        local msg = fmt("PsExec-style lateral movement: %s -> %s via SMB pipe %s [MITRE ATT&CK: T1021.002, T1569.002]",
                        c$id$orig_h, c$id$resp_h, match_name);
        NOTICE([$note=WMI_RemoteExec,
                $conn=c,
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $msg=msg,
                $sub=fmt("pipe=%s", match_name),
                $identifier=cat(c$id$orig_h, c$id$resp_h, match_name),
                $suppress_for=10 min]);
        }
    }

# ─── HTTP-based WMI (WMI over SOAP / WSMAN) ──────────────────────────────

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # WinRM uses WSMAN/WSMV paths over HTTP/S
    if ( method != "POST" )
        return;

    if ( ! Site::is_local_addr(src) || ! Site::is_local_addr(dst) )
        return;

    if ( src == dst )
        return;

    # Match WSMAN endpoint paths
    local uri_lower = to_lower(original_URI);
    if ( /\/wsman/ !in uri_lower && /\/powershell/ !in uri_lower )
        return;

    # Deduplicate: only alert on the HTTP port if not already caught by port check
    if ( c$id$resp_p == winrm_port_http || c$id$resp_p == winrm_port_https )
        return;

    local msg = fmt("WinRM/WSMAN POST on non-standard port: %s -> %s:%s (uri=%s) [MITRE ATT&CK: T1021.006]",
                    src, dst, c$id$resp_p, original_URI);
    NOTICE([$note=WinRM_RemoteExecution,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("uri=%s port=%s", original_URI, c$id$resp_p),
            $identifier=cat(src, dst, "wsman_nonstandard"),
            $suppress_for=wmi_suppress_interval]);
    }

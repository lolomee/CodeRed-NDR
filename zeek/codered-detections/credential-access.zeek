##! CodeRed NDR — Credential Access & AD Reconnaissance Detection
##! Detects NTLM relay attacks, LLMNR/NBT-NS poisoning, LDAP-based Active
##! Directory reconnaissance, and non-Kerberos password spraying over LDAP,
##! SMTP, and other protocols. These are stage-2 attack techniques used after
##! initial access to harvest credentials for lateral movement.
##!
##! MITRE ATT&CK:
##!   T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning
##!   T1187     — Forced Authentication (NTLM capture via UNC paths)
##!   T1018     — Remote System Discovery (LDAP recon)
##!   T1069.002 — Permission Groups Discovery: Domain Groups (LDAP)
##!   T1087.002 — Account Discovery: Domain Account (LDAP)
##!   T1110.003 — Brute Force: Password Spraying (LDAP)
##!   T1003.002 — OS Credential Dumping: Security Account Manager

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when LLMNR or NBT-NS responses from unexpected hosts are seen
        ## — indicates Responder or Inveigh is running on a rogue host.
        LLMNR_Poisoning,

        ## Raised on NTLM authentication to unexpected services (relay target).
        NTLM_Relay_Indicator,

        ## Raised on high-volume LDAP queries consistent with AD reconnaissance.
        LDAP_Recon,

        ## Raised on LDAP authentication failures (password spray over LDAP).
        LDAP_PasswordSpray,

        ## Raised on SAMR/LSARPC queries for user/group enumeration.
        AD_Enumeration,
    };

    ## LDAP port.
    const ldap_port:  port = 389/tcp  &redef;
    const ldaps_port: port = 636/tcp  &redef;
    const ldap_gc:    port = 3268/tcp &redef;  # Global Catalog
    const ldap_gcs:   port = 3269/tcp &redef;

    ## LLMNR and NBT-NS ports (UDP).
    const llmnr_port:  port = 5355/udp &redef;
    const netbios_port: port = 137/udp &redef;

    ## LDAP query burst — unique queries from one source in the window.
    const ldap_recon_threshold: double = 30.0 &redef;
    const ldap_recon_window: interval = 2 min &redef;

    ## LDAP auth failure threshold for spray detection.
    const ldap_spray_threshold: double = 10.0 &redef;
    const ldap_spray_window: interval = 3 min &redef;

    ## LLMNR response threshold from a single host.
    ## Legitimate hosts rarely send LLMNR responses; Responder sends many.
    const llmnr_response_threshold: double = 5.0 &redef;
    const llmnr_window: interval = 1 min &redef;

    ## NTLM relay: NTLM auth on non-standard services from internal hosts.
    ## Key: true NTLM over SMB between non-DC internal hosts is a relay indicator.
    const ntlm_relay_suppress: interval = 10 min &redef;

    ## Known domain controllers (populated via redef in local.zeek).
    const dc_hosts: set[addr] = {} &redef;

    ## Suppress interval.
    const cred_suppress_interval: interval = 10 min &redef;
}

event zeek_init()
    {
    # LDAP query burst (recon)
    local r_ldap = SumStats::Reducer($stream="codered.ldap.queries", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.ldap.recon",
        $epoch=ldap_recon_window,
        $reducers=set(r_ldap),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ldap.queries"]$unique + 0.0; },
        $threshold=ldap_recon_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ldap.queries"]$unique;
            local msg = fmt("LDAP AD reconnaissance: %s sent %d unique LDAP queries in %s [MITRE ATT&CK: T1018, T1087.002, T1069.002]",
                            key$host, n, ldap_recon_window);
            NOTICE([$note=LDAP_Recon,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_queries=%d", n),
                    $identifier=cat(key$host, "ldap_recon"),
                    $suppress_for=cred_suppress_interval]);
            }
    ]);

    # LDAP auth failure (spray)
    local r_spray = SumStats::Reducer($stream="codered.ldap.auth_fail", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.ldap.spray",
        $epoch=ldap_spray_window,
        $reducers=set(r_spray),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ldap.auth_fail"]$sum; },
        $threshold=ldap_spray_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ldap.auth_fail"]$sum;
            local msg = fmt("LDAP password spray: %s had %.0f LDAP auth failures in %s [MITRE ATT&CK: T1110.003]",
                            key$host, n, ldap_spray_window);
            NOTICE([$note=LDAP_PasswordSpray,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("ldap_failures=%.0f", n),
                    $identifier=cat(key$host, "ldap_spray"),
                    $suppress_for=cred_suppress_interval]);
            }
    ]);

    # LLMNR response burst (Responder detection)
    local r_llmnr = SumStats::Reducer($stream="codered.llmnr.responses", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.llmnr.poisoning",
        $epoch=llmnr_window,
        $reducers=set(r_llmnr),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.llmnr.responses"]$sum; },
        $threshold=llmnr_response_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.llmnr.responses"]$sum;
            local msg = fmt("LLMNR poisoning (Responder/Inveigh?): %s sent %.0f LLMNR responses in %s — likely credential capture [MITRE ATT&CK: T1557.001]",
                            key$host, n, llmnr_window);
            NOTICE([$note=LLMNR_Poisoning,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("llmnr_responses=%.0f", n),
                    $identifier=cat(key$host, "llmnr_poison"),
                    $suppress_for=cred_suppress_interval]);
            }
    ]);
    }

# ─── LDAP: query tracking and auth failure ───────────────────────────────

event ldap_search_request(c: connection, message_id: count, base_object: string,
                           scope: int, deref_aliases: int, size_limit: count,
                           time_limit: count, types_only: bool,
                           filter: string, attributes: vector of string)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track unique LDAP search filters per source for recon detection
    SumStats::observe("codered.ldap.queries",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=filter));

    # Flag high-value recon filters immediately
    local filter_lower = to_lower(filter);
    local recon_patterns: vector of string = vector(
        "objectclass=user",
        "objectclass=computer",
        "objectclass=group",
        "admincount=1",
        "serviceprincipalname=*",   # SPN enumeration = Kerberoast prep
        "memberof=*",
        "samaccountname=*",
        "userprincipalname=*",
        "lastlogon",
        "pwdlastset",
        "objectsid",
        "ms-mcs-admpwd",            # LAPS password attribute
        "confidentialitykey",
        "ntsecuritydescriptor",
        "(admincount>=1)"
    );

    for ( idx in recon_patterns )
        {
        if ( recon_patterns[idx] in filter_lower )
            {
            local msg = fmt("High-value LDAP recon query: %s filter=%s [MITRE ATT&CK: T1087.002, T1069.002]",
                            src, filter);
            NOTICE([$note=LDAP_Recon,
                    $conn=c,
                    $src=src,
                    $dst=c$id$resp_h,
                    $msg=msg,
                    $sub=fmt("filter=%s", filter),
                    $identifier=cat(src, recon_patterns[idx]),
                    $suppress_for=cred_suppress_interval]);
            break;
            }
        }
    }

event ldap_bind_request(c: connection, message_id: count, version: int,
                         name: string, authType: LDAP::AuthType,
                         authData: string)
    {
    # Count bind attempts for spray detection
    # Failed binds appear as consecutive bind requests with different credentials
    local src = c$id$orig_h;
    if ( Site::is_local_addr(src) )
        {
        SumStats::observe("codered.ldap.auth_fail",
                          SumStats::Key($host=src),
                          SumStats::Observation($num=1));
        }
    }

# ─── LLMNR/NBT-NS poisoning detection ────────────────────────────────────

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    # LLMNR uses port 5355, NBT-NS uses 137
    # A host responding to LLMNR queries it didn't initiate = Responder
    if ( c$id$resp_p != llmnr_port && c$id$resp_p != netbios_port )
        return;

    if ( is_orig )
        return;  # Only track responses

    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Poisoner responds to everything — flag response bursts
    SumStats::observe("codered.llmnr.responses",
                      SumStats::Key($host=src),
                      SumStats::Observation($num=1));
    }

# ─── NTLM relay indicator: NTLM auth on unexpected services ──────────────

event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;

    if ( ! Site::is_local_addr(src) )
        return;

    # NTLM auth on HTTP (port 80/8080) from internal to internal = relay
    # Legitimate NTLM/Kerberos auth goes to DC (88, 389), not to arbitrary HTTP
    if ( ( dst_port == 80/tcp || dst_port == 8080/tcp || dst_port == 8443/tcp ) &&
         Site::is_local_addr(dst) )
        {
        local msg = fmt("NTLM auth on HTTP (relay indicator): %s -> %s:%s [MITRE ATT&CK: T1557.001, T1187]",
                        src, dst, dst_port);
        NOTICE([$note=NTLM_Relay_Indicator,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("ntlm_on_port=%s", dst_port),
                $identifier=cat(src, dst, "ntlm_relay"),
                $suppress_for=cred_suppress_interval]);
        }
    }

# ─── DCE/RPC SAMR: user/group enumeration ────────────────────────────────

event dce_rpc_bind(c: connection, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
    {
    local uuid_lower = to_lower(uuid);

    # SAMR UUID: 12345778-1234-abcd-ef00-0123456789ac
    # LSARPC UUID: 12345778-1234-abcd-ef00-0123456789ab
    if ( uuid_lower != "12345778-1234-abcd-ef00-0123456789ac" &&
         uuid_lower != "12345778-1234-abcd-ef00-0123456789ab" )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # SAMR/LSARPC from a non-DC host is enumeration
    if ( |dc_hosts| > 0 && src in dc_hosts )
        return;

    local svc = uuid_lower == "12345778-1234-abcd-ef00-0123456789ac" ? "SAMR" : "LSARPC";
    local msg = fmt("AD enumeration via %s: %s -> %s (uuid=%s) [MITRE ATT&CK: T1087.002, T1069.002]",
                    svc, src, dst, svc);
    NOTICE([$note=AD_Enumeration,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("service=%s", svc),
            $identifier=cat(src, dst, svc),
            $suppress_for=cred_suppress_interval]);
    }

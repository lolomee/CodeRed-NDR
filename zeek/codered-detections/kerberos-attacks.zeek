##! CodeRed NDR — Kerberos Attack Detection
##! Detects Active Directory Kerberos-based attacks: Kerberoasting,
##! AS-REP Roasting, Golden/Silver Ticket abuse, and Kerberos enumeration.
##! These are among the most common APT and insider threat techniques
##! in Windows AD environments.
##!
##! MITRE ATT&CK:
##!   T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket
##!   T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket
##!   T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
##!   T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting
##!   T1078     — Valid Accounts (forged ticket abuse)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised on Kerberoasting indicators (TGS-REQ for RC4 on SPN accounts).
        Kerberos_Roasting,

        ## Raised when AS-REP roasting is detected (pre-auth disabled accounts).
        Kerberos_ASREP_Roasting,

        ## Raised when Golden/Silver Ticket indicators are detected.
        Kerberos_Forged_Ticket,

        ## Raised on abnormal Kerberos enumeration (many unique SPNs or principals).
        Kerberos_Enumeration,

        ## Raised when Kerberos traffic is seen from an unexpected source.
        Kerberos_Anomaly,
    };

    ## Kerberos port.
    const kerberos_port: port = 88/tcp &redef;
    const kerberos_udp_port: port = 88/udp &redef;

    ## RC4 encryption type (etype 23) in TGS requests signals Kerberoasting.
    ## Legitimate modern environments use AES (etypes 17, 18).
    const krb5_etype_rc4: count = 23;
    const krb5_etype_des: count = 3;

    ## Minimum RC4 TGS requests from a single source in the window to alert.
    const kerberoast_threshold: double = 3.0 &redef;

    ## Minimum AS-REP requests from a single source (AS-REP roasting spray).
    const asrep_threshold: double = 5.0 &redef;

    ## Unique SPN/principal requests within window before flagging enumeration.
    const kerb_enum_threshold: double = 20.0 &redef;

    ## Time window for Kerberos attack detection.
    const kerb_window: interval = 5 min &redef;

    ## Suppress interval for repeated notices.
    const kerb_suppress_interval: interval = 15 min &redef;

    ## Known Domain Controllers — Kerberos from non-DC to non-DC is anomalous.
    ## Populate via redef in local.zeek:
    ##   redef CodeRed::known_dcs += { 10.0.0.1, 10.0.0.2 };
    const known_dcs: set[addr] = {} &redef;

    ## Kerberos ticket lifetime considered suspicious if beyond this (Golden Ticket).
    ## Legitimate tickets max at 10 hours. Attackers set 10 years.
    const max_ticket_lifetime_hours: double = 12.0 &redef;
}

# ─── SumStats initialisation ──────────────────────────────────────────────

event zeek_init()
    {
    # ── Kerberoasting: count RC4 TGS requests per source ──
    local r_rc4 = SumStats::Reducer($stream="codered.kerb.rc4_tgs", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.kerb.kerberoasting",
        $epoch=kerb_window,
        $reducers=set(r_rc4),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.kerb.rc4_tgs"]$sum; },
        $threshold=kerberoast_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.kerb.rc4_tgs"]$sum;
            local msg = fmt("Kerberoasting: %s requested %.0f RC4 (etype 23) TGS tickets in %s — offline cracking likely [MITRE ATT&CK: T1558.003]",
                            key$host, n, kerb_window);
            NOTICE([$note=Kerberos_Roasting,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("rc4_tgs_count=%.0f window=%s", n, kerb_window),
                    $identifier=cat(key$host, "kerberoast"),
                    $suppress_for=kerb_suppress_interval]);
            }
    ]);

    # ── AS-REP Roasting: count AS-REQ without pre-auth ──
    local r_asrep = SumStats::Reducer($stream="codered.kerb.asrep", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.kerb.asrep_roasting",
        $epoch=kerb_window,
        $reducers=set(r_asrep),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.kerb.asrep"]$sum; },
        $threshold=asrep_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.kerb.asrep"]$sum;
            local msg = fmt("AS-REP Roasting: %s sent %.0f AS-REQ without pre-auth in %s — harvesting hashes [MITRE ATT&CK: T1558.004]",
                            key$host, n, kerb_window);
            NOTICE([$note=Kerberos_ASREP_Roasting,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("asrep_count=%.0f window=%s", n, kerb_window),
                    $identifier=cat(key$host, "asrep"),
                    $suppress_for=kerb_suppress_interval]);
            }
    ]);

    # ── Kerberos enumeration: unique principals requested per source ──
    local r_enum = SumStats::Reducer($stream="codered.kerb.principals", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.kerb.enumeration",
        $epoch=kerb_window,
        $reducers=set(r_enum),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.kerb.principals"]$unique + 0.0; },
        $threshold=kerb_enum_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.kerb.principals"]$unique;
            local msg = fmt("Kerberos enumeration: %s queried %d unique principals/SPNs in %s [MITRE ATT&CK: T1558.003, T1087]",
                            key$host, n, kerb_window);
            NOTICE([$note=Kerberos_Enumeration,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_principals=%d", n),
                    $identifier=cat(key$host, "kerb_enum"),
                    $suppress_for=kerb_suppress_interval]);
            }
    ]);
    }

# ─── Kerberos event hooks ──────────────────────────────────────────────────

event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # ── Kerberoasting: RC4/DES encryption type in TGS-REQ ──
    # Attackers request RC4 (etype 23) to get a ticket encrypted with the
    # service account's NTLM hash — crackable offline with hashcat.
    if ( msg?$etypes )
        {
        for ( idx in msg$etypes )
            {
            local etype = msg$etypes[idx];
            if ( etype == krb5_etype_rc4 || etype == krb5_etype_des )
                {
                SumStats::observe("codered.kerb.rc4_tgs",
                                  SumStats::Key($host=src),
                                  SumStats::Observation($num=1));
                break;
                }
            }
        }

    # ── Track unique SPNs requested (enumeration) ──
    if ( msg?$service && |msg$service| > 0 )
        {
        local svc = msg$service[0];
        SumStats::observe("codered.kerb.principals",
                          SumStats::Key($host=src),
                          SumStats::Observation($str=svc));
        }
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # ── AS-REP Roasting: AS-REQ without PA-ENC-TIMESTAMP (pre-auth disabled) ──
    # When pre-auth is disabled, the KDC responds with an AS-REP containing
    # a hash crackable offline. Attackers spray usernames to find vulnerable accounts.
    local has_preauth = F;
    if ( msg?$padata )
        {
        for ( idx in msg$padata )
            {
            # PA-ENC-TIMESTAMP padata type = 2
            if ( msg$padata[idx]$ptype == 2 )
                {
                has_preauth = T;
                break;
                }
            }
        }

    if ( ! has_preauth )
        {
        SumStats::observe("codered.kerb.asrep",
                          SumStats::Key($host=src),
                          SumStats::Observation($num=1));
        }

    # Track unique client principals for enumeration
    if ( msg?$client && msg$client?$name_string && |msg$client$name_string| > 0 )
        {
        SumStats::observe("codered.kerb.principals",
                          SumStats::Key($host=src),
                          SumStats::Observation($str=msg$client$name_string[0]));
        }
    }

event krb_tgt_reply(c: connection, msg: KRB::KDC_Response)
    {
    # ── Golden/Silver Ticket: abnormally long ticket lifetime ──
    # Legitimate AD tickets max at 10 hours (configurable, usually 8–10h).
    # Mimikatz Golden Tickets default to 10 years. Any ticket lifetime
    # beyond max_ticket_lifetime_hours is highly suspicious.
    if ( ! msg?$ticket )
        return;

    if ( ! msg$ticket?$enc_part )
        return;

    # Zeek KRB records expose ticket endtime if decryptable (domain joined sensor)
    # or we detect anomaly via the encrypted blob size / structure heuristic.
    # For network-level detection we look at the authtime vs endtime delta
    # in the unencrypted portions of the KDC reply.
    if ( msg?$till && msg?$from )
        {
        local lifetime_secs = interval_to_double(msg$till - msg$from);
        local lifetime_hours = lifetime_secs / 3600.0;

        if ( lifetime_hours > max_ticket_lifetime_hours )
            {
            local src = c$id$orig_h;
            local dst = c$id$resp_h;
            local msg_str = fmt("Golden/Silver Ticket: Kerberos ticket lifetime %.1f hours from %s (normal max: %.0fh) [MITRE ATT&CK: T1558.001, T1558.002]",
                                lifetime_hours, src, max_ticket_lifetime_hours);
            NOTICE([$note=Kerberos_Forged_Ticket,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg_str,
                    $sub=fmt("lifetime_hours=%.1f", lifetime_hours),
                    $identifier=cat(src, "golden_ticket"),
                    $suppress_for=kerb_suppress_interval]);
            }
        }
    }

event krb_error(c: connection, msg: KRB::KRB_Error)
    {
    # ── Non-DC to Non-DC Kerberos: anomaly ──
    # In healthy AD environments, Kerberos only flows client → DC and
    # service → DC (for validation). Peer-to-peer Kerberos is anomalous
    # and can indicate Pass-the-Ticket or ticket injection attacks.
    if ( |known_dcs| == 0 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( src in known_dcs || dst in known_dcs )
        return;

    if ( ! Site::is_local_addr(src) || ! Site::is_local_addr(dst) )
        return;

    local err_msg = fmt("Kerberos between non-DC hosts: %s -> %s (error code=%s) — possible Pass-the-Ticket [MITRE ATT&CK: T1550.003]",
                        src, dst, msg$error_code);
    NOTICE([$note=Kerberos_Anomaly,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=err_msg,
            $sub=fmt("error=%s", msg$error_code),
            $identifier=cat(src, dst, "kerb_anomaly"),
            $suppress_for=kerb_suppress_interval]);
    }

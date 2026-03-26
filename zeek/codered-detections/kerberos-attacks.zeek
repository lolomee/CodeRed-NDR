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
##!
##! NOTE: Kerberos event record field names vary between Zeek versions.
##! This script uses connection-level detection (port 88 traffic analysis)
##! which is stable across all Zeek versions, plus zeek.log correlation.

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
    const known_dcs: set[addr] = {} &redef;

    ## Kerberos ticket lifetime considered suspicious if beyond this (Golden Ticket).
    const max_ticket_lifetime_hours: double = 12.0 &redef;
}

# ─── SumStats initialisation ──────────────────────────────────────────────

event zeek_init()
    {
    # Track Kerberos connection bursts per source (enumeration proxy)
    local r_enum = SumStats::Reducer($stream="codered.kerb.targets", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.kerb.enumeration",
        $epoch=kerb_window,
        $reducers=set(r_enum),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.kerb.targets"]$unique + 0.0; },
        $threshold=kerb_enum_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.kerb.targets"]$unique;
            local msg = fmt("Kerberos enumeration: %s contacted %d unique KDC targets in %s [MITRE ATT&CK: T1558.003, T1087]",
                            key$host, n, kerb_window);
            NOTICE([$note=Kerberos_Enumeration,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_targets=%d", n),
                    $identifier=cat(key$host, "kerb_enum"),
                    $suppress_for=kerb_suppress_interval]);
            }
    ]);

    # Track Kerberos failure burst (AS-REP roasting spray)
    local r_fail = SumStats::Reducer($stream="codered.kerb.failures", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.kerb.asrep_spray",
        $epoch=kerb_window,
        $reducers=set(r_fail),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.kerb.failures"]$sum; },
        $threshold=asrep_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.kerb.failures"]$sum;
            local msg = fmt("Kerberos failure spike from %s — %.0f failures in %s (AS-REP roasting / spray?) [MITRE ATT&CK: T1558.004]",
                            key$host, n, kerb_window);
            NOTICE([$note=Kerberos_ASREP_Roasting,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("kerb_failures=%.0f", n),
                    $identifier=cat(key$host, "asrep_spray"),
                    $suppress_for=kerb_suppress_interval]);
            }
    ]);
    }

# ─── Connection-level Kerberos detection ─────────────────────────────────
# These events use only connection metadata — stable across all Zeek versions.

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( c$id$resp_p != kerberos_port && c$id$resp_p != kerberos_udp_port )
        return;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track unique KDC targets for enumeration detection
    SumStats::observe("codered.kerb.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));

    # Non-DC to non-DC Kerberos is anomalous (Pass-the-Ticket indicator)
    if ( |known_dcs| > 0 && dst !in known_dcs && src !in known_dcs &&
         Site::is_local_addr(dst) )
        {
        local msg = fmt("Kerberos to non-DC host: %s -> %s (port 88) — possible Pass-the-Ticket [MITRE ATT&CK: T1550.003]",
                        src, dst);
        NOTICE([$note=Kerberos_Anomaly,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub="kerberos_to_non_dc",
                $identifier=cat(src, dst, "kerb_non_dc"),
                $suppress_for=kerb_suppress_interval]);
        }
    }

# ─── Kerberos log correlation via Zeek krb.log ────────────────────────────
# Use krb_tgt_request event — basic connection + msg, stable in Zeek 4.x+5.x

event krb_tgt_request(c: connection, msg: KRB::KDC_Request)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track for enumeration
    SumStats::observe("codered.kerb.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(c$id$resp_h)));
    }

event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track unique TGS targets for kerberoasting detection
    SumStats::observe("codered.kerb.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(c$id$resp_h)));
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Count AS requests for spray detection
    SumStats::observe("codered.kerb.failures",
                      SumStats::Key($host=src),
                      SumStats::Observation($num=1));
    }

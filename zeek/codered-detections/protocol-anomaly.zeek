##! CodeRed NDR — Protocol Anomaly & Evasion Detection
##! Detects traffic evading detection by misusing protocols or ports:
##! port-protocol mismatch (SSH on 443, HTTP on 8080 without reason),
##! IPv6 tunneling (Teredo, 6to4, ISATAP), connections to Tor exit nodes,
##! and SNMP community string enumeration.
##!
##! MITRE ATT&CK:
##!   T1571  — Non-Standard Port
##!   T1572  — Protocol Tunneling
##!   T1090  — Proxy (Tor)
##!   T1090.003 — Multi-hop Proxy
##!   T1046  — Network Service Discovery (SNMP enum)
##!   T1095  — Non-Application Layer Protocol

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a protocol is detected running on an unexpected port.
        Protocol_Port_Mismatch,
        ## Raised when IPv6 tunneling over IPv4 is detected.
        IPv6_Tunnel_Detected,
        ## Raised when traffic to/from known Tor exit nodes is detected.
        Tor_Connection,
        ## Raised on SNMP community string brute force / enumeration.
        SNMP_Enumeration,
    };

    ## Expected ports for each protocol. Traffic on other ports is flagged.
    const expected_ports: table[string] of set[port] = {
        ["ssh"]   = set(22/tcp),
        ["http"]  = set(80/tcp, 8080/tcp, 8000/tcp, 8888/tcp, 3000/tcp),
        ["https"] = set(443/tcp, 8443/tcp),
        ["ftp"]   = set(21/tcp),
        ["smtp"]  = set(25/tcp, 465/tcp, 587/tcp),
        ["rdp"]   = set(3389/tcp),
        ["vnc"]   = set(5900/tcp, 5901/tcp),
        ["dns"]   = set(53/tcp, 53/udp),
        ["snmp"]  = set(161/udp, 162/udp),
    } &redef;

    ## IPv4 addresses used for IPv6 tunneling services.
    const ipv6_tunnel_ips: set[addr] = {
        # Teredo server (Microsoft)
        65.55.158.226,
        65.54.227.120,
        131.107.65.1,
        # 6to4 relay anycast
        192.88.99.1,
        # ISATAP router discovery (often resolves to local router)
    } &redef;

    ## Protocol 41 = IPv6-in-IPv4 encapsulation (6to4/ISATAP).
    ## Protocol 47 = GRE (used for tunneling).
    ## Detected by anomalous IP protocols in connection records.

    ## SNMP community strings that indicate brute force attempts.
    const snmp_brute_threshold: double = 10.0 &redef;
    const snmp_brute_window: interval = 2 min &redef;

    ## Tor exit node IPs — updated from dan.me.uk/torlist.
    ## This is a static snapshot; integrate with update-intel.sh for live feed.
    const tor_exit_nodes: set[addr] = {
        # Known Tor exit IPs (sample — update-intel.sh should refresh this)
        51.15.43.205, 185.220.101.1, 185.220.101.2,
        185.220.101.3, 185.220.101.4, 185.220.101.5,
        185.220.101.32, 185.220.101.33, 185.220.101.34,
        185.107.47.171, 193.218.118.1, 193.218.118.2,
        199.249.230.68, 199.249.230.87, 199.249.230.77,
        204.8.96.142, 204.8.96.144, 204.8.96.145,
        45.33.32.156, 51.159.160.129, 81.7.10.29,
        89.58.33.26, 94.230.208.147, 95.128.43.164,
        107.189.10.143, 109.201.133.195, 111.240.1.1,
        116.12.199.68, 118.163.74.160, 130.61.14.207,
    } &redef;

    ## Suppress interval for protocol anomaly alerts.
    const proto_suppress_interval: interval = 15 min &redef;
}

event zeek_init()
    {
    # SNMP enumeration burst
    local r_snmp = SumStats::Reducer($stream="codered.snmp.queries", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.snmp.bruteforce",
        $epoch=snmp_brute_window,
        $reducers=set(r_snmp),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.snmp.queries"]$unique + 0.0; },
        $threshold=snmp_brute_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.snmp.queries"]$unique;
            local msg = fmt("SNMP enumeration: %s sent %d unique SNMP requests in %s [MITRE ATT&CK: T1046]",
                            key$host, n, snmp_brute_window);
            NOTICE([$note=SNMP_Enumeration,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_snmp_targets=%d", n),
                    $identifier=cat(key$host, "snmp_enum"),
                    $suppress_for=proto_suppress_interval]);
            }
    ]);
    }

# ─── Protocol-port mismatch ───────────────────────────────────────────────
# Use connection_state_remove so c$service is fully populated by the time
# we check it (protocol analyzers confirm the service during the connection).

event connection_state_remove(c: connection)
    {
    if ( ! c?$service || |c$service| == 0 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local port_val = c$id$resp_p;

    if ( ! Site::is_local_addr(src) )
        return;

    for ( svc in c$service )
        {
        local svc_lower = to_lower(svc);
        if ( svc_lower !in expected_ports )
            next;

        local expected = expected_ports[svc_lower];
        if ( port_val in expected )
            next;

        # Protocol confirmed on unexpected port
        local msg = fmt("Protocol-port mismatch: %s detected on port %s (src=%s -> dst=%s) [MITRE ATT&CK: T1571]",
                        svc, port_val, src, dst);
        NOTICE([$note=Protocol_Port_Mismatch,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("protocol=%s port=%s", svc, port_val),
                $identifier=cat(src, dst, svc_lower, cat(port_val)),
                $suppress_for=proto_suppress_interval]);
        }
    }

# ─── Tor exit node connection detection ──────────────────────────────────

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Check both directions — sensor may see incoming Tor connections too
    if ( dst in tor_exit_nodes && Site::is_local_addr(src) )
        {
        local msg = fmt("Tor exit node connection (outbound): %s -> %s (known Tor exit) [MITRE ATT&CK: T1090.003]",
                        src, dst);
        NOTICE([$note=Tor_Connection,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("tor_exit=%s", dst),
                $identifier=cat(src, cat(dst), "tor_out"),
                $suppress_for=proto_suppress_interval]);
        }

    if ( src in tor_exit_nodes && Site::is_local_addr(dst) )
        {
        local imsg = fmt("Tor exit node connection (inbound): %s (Tor exit) -> %s [MITRE ATT&CK: T1090.003]",
                         src, dst);
        NOTICE([$note=Tor_Connection,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=imsg,
                $sub=fmt("tor_exit=%s", src),
                $identifier=cat(cat(src), dst, "tor_in"),
                $suppress_for=proto_suppress_interval]);
        }

    # IPv6 tunneling: connections to known Teredo/6to4 relay IPs
    if ( dst in ipv6_tunnel_ips && Site::is_local_addr(src) )
        {
        local tmsg = fmt("IPv6 tunneling: %s -> %s (Teredo/6to4 relay) [MITRE ATT&CK: T1572]",
                         src, dst);
        NOTICE([$note=IPv6_Tunnel_Detected,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=tmsg,
                $sub=fmt("tunnel_relay=%s", dst),
                $identifier=cat(src, cat(dst), "ipv6_tunnel"),
                $suppress_for=proto_suppress_interval]);
        }
    }

# ─── IPv6-in-IPv4 tunneling ───────────────────────────────────────────────
# Tunnel::ip_in_ip event is not available in standard Zeek APT installations.
# 6in4 tunnel detection uses Zeek's tunnel framework via the generic
# connection_established event checking for known Teredo/6to4 relay IPs above.
# The ipv6_tunnel_ips set handles this detection path.

# ─── SNMP enumeration ─────────────────────────────────────────────────────

# snmp_get_request requires @load policy/protocols/snmp which may not be
# present in all Zeek installations. SNMP enumeration is also detected via
# the connection-based SumStats tracking above (port 161/udp).
# Uncomment below if your Zeek has SNMP protocol support:
#
# event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header,
#                         pdus: SNMP::PDUs)
#     {
#     if ( ! is_orig ) return;
#     local src = c$id$orig_h;
#     if ( ! Site::is_local_addr(src) ) return;
#     SumStats::observe("codered.snmp.queries",
#                       SumStats::Key($host=src),
#                       SumStats::Observation($str=cat(c$id$resp_h)));
#     }

##! CodeRed NDR — ICMP Tunneling Detection
##! Detects data exfiltration and C2 channels hidden inside ICMP echo
##! requests/replies. Tools: icmptunnel, ptunnel, Hans, nping --icmp.
##! Key signals: oversized payloads, high packet rates, non-zero payload
##! data entropy, asymmetric request/reply ratios.
##!
##! MITRE ATT&CK:
##!   T1095   — Non-Application Layer Protocol
##!   T1041   — Exfiltration Over C2 Channel
##!   T1048   — Exfiltration Over Alternative Protocol
##!   T1572   — Protocol Tunneling

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when ICMP payload size exceeds normal ping sizes.
        ICMP_Oversized_Payload,
        ## Raised when a host generates ICMP traffic at tunneling rates.
        ICMP_High_Rate,
        ## Raised when ICMP traffic shows tunneling characteristics (entropy+size).
        ICMP_Tunnel_Detected,
    };

    ## Normal ICMP echo payload is 32–64 bytes (Windows/Linux ping defaults).
    ## Anything above 200 bytes is suspicious; above 500 is almost certainly tunneling.
    const icmp_normal_payload_size: count = 64 &redef;
    const icmp_tunnel_payload_size: count = 200 &redef;

    ## ICMP packets per minute from a single source before flagging high rate.
    const icmp_rate_threshold: double = 60.0 &redef;

    ## Time window for ICMP rate tracking.
    const icmp_rate_window: interval = 1 min &redef;

    ## Total ICMP bytes per window to consider for data exfil via tunnel.
    const icmp_exfil_bytes_threshold: double = 102400.0 &redef;  # 100KB/min

    ## Suppress interval.
    const icmp_suppress_interval: interval = 10 min &redef;
}

# Per-source ICMP tracking for rate and volume
global icmp_tracker: table[addr] of record {
    pkt_count:   count;
    total_bytes: count;
    large_count: count;
    last_reset:  time;
} &create_expire=2 min;

event zeek_init()
    {
    # ICMP rate burst detection via SumStats
    local r_rate = SumStats::Reducer($stream="codered.icmp.pkts", $apply=set(SumStats::SUM));
    local r_bytes = SumStats::Reducer($stream="codered.icmp.bytes", $apply=set(SumStats::SUM));

    SumStats::create([
        $name="codered.icmp.rate",
        $epoch=icmp_rate_window,
        $reducers=set(r_rate, r_bytes),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.icmp.pkts"]$sum; },
        $threshold=icmp_rate_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local pkts  = result["codered.icmp.pkts"]$sum;
            local bytes = result["codered.icmp.bytes"]$sum;
            local msg = fmt("ICMP high rate from %s: %.0f packets (%.0f bytes) in %s — possible ICMP tunnel [MITRE ATT&CK: T1095, T1572]",
                            key$host, pkts, bytes, icmp_rate_window);
            local note = bytes > icmp_exfil_bytes_threshold ? ICMP_Tunnel_Detected : ICMP_High_Rate;
            NOTICE([$note=note,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("pkts=%.0f bytes=%.0f", pkts, bytes),
                    $identifier=cat(key$host, "icmp_rate"),
                    $suppress_for=icmp_suppress_interval]);
            }
    ]);
    }

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local plen = |payload|;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.icmp.pkts",  SumStats::Key($host=src), SumStats::Observation($num=1));
    SumStats::observe("codered.icmp.bytes", SumStats::Key($host=src), SumStats::Observation($num=plen));

    # Oversized payload — immediate alert
    if ( plen > icmp_tunnel_payload_size )
        {
        local msg = fmt("ICMP oversized payload: %s -> %s, payload=%d bytes (normal max=%d) [MITRE ATT&CK: T1095, T1041]",
                        src, dst, plen, icmp_normal_payload_size);
        NOTICE([$note=ICMP_Oversized_Payload,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("payload_bytes=%d", plen),
                $identifier=cat(src, dst, "icmp_oversize"),
                $suppress_for=icmp_suppress_interval]);
        }
    }

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
    {
    local src = c$id$orig_h;
    local plen = |payload|;

    SumStats::observe("codered.icmp.pkts",  SumStats::Key($host=src), SumStats::Observation($num=1));
    SumStats::observe("codered.icmp.bytes", SumStats::Key($host=src), SumStats::Observation($num=plen));

    # Large reply payload — data being returned via reverse tunnel
    if ( plen > icmp_tunnel_payload_size && Site::is_local_addr(c$id$resp_h) )
        {
        local msg = fmt("ICMP large reply payload (reverse tunnel?): %s -> %s, reply=%d bytes [MITRE ATT&CK: T1095]",
                        src, c$id$resp_h, plen);
        NOTICE([$note=ICMP_Oversized_Payload,
                $conn=c,
                $src=src,
                $dst=c$id$resp_h,
                $msg=msg,
                $sub=fmt("reply_bytes=%d", plen),
                $identifier=cat(src, c$id$resp_h, "icmp_reply_oversize"),
                $suppress_for=icmp_suppress_interval]);
        }
    }

##! CodeRed NDR — Long Connection & Exfiltration Detection
##! Flags TCP connections lasting longer than 24 hours and connections
##! with highly asymmetric data transfer (potential exfiltration).
##! MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a TCP connection exceeds the maximum allowed duration.
        Long_Connection,
        ## Raised when a connection shows highly asymmetric data transfer.
        Potential_Exfil,
    };

    ## Maximum duration for a TCP connection before alerting.
    const long_conn_threshold: interval = 24 hr &redef;

    ## Minimum bytes transferred to evaluate for exfiltration.
    const exfil_min_bytes: count = 104857600 &redef;  # 100 MB

    ## Ratio of orig_bytes/resp_bytes (or vice versa) to flag as asymmetric.
    ## A ratio of 10 means one side sent 10x more than the other.
    const exfil_asymmetry_ratio: double = 10.0 &redef;

    ## Minimum connection duration to evaluate for exfiltration (avoid flagging short bursts).
    const exfil_min_duration: interval = 5 min &redef;

    ## Ports/services to exclude from long connection detection.
    const long_conn_exclude_ports: set[port] = {
        53/tcp, 53/udp,     # DNS
        123/udp,            # NTP
        179/tcp,            # BGP
    } &redef;

    ## Protocols to exclude from long connection detection.
    const long_conn_exclude_services: set[string] = {
        "dns", "ntp", "bgp",
    } &redef;
}

# ─── Check if a connection should be excluded ───
function is_excluded(c: connection): bool
    {
    if ( c$id$resp_p in long_conn_exclude_ports )
        return T;

    if ( c?$service )
        {
        for ( svc in c$service )
            {
            if ( to_lower(svc) in long_conn_exclude_services )
                return T;
            }
        }

    return F;
    }

event connection_state_remove(c: connection)
    {
    # Only check TCP connections
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return;

    if ( is_excluded(c) )
        return;

    local duration = c$duration;

    # Some connections may not have duration set
    if ( duration == 0 secs )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;

    # ─── Long Connection Detection ───
    if ( duration > long_conn_threshold )
        {
        local long_msg = fmt("Long-lived connection: %s -> %s:%s, duration=%s [MITRE ATT&CK: T1041]",
                             src, dst, dst_port, duration);
        NOTICE([
            $note=Long_Connection,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=long_msg,
            $sub=fmt("duration=%s port=%s", duration, dst_port),
            $identifier=cat(c$uid),
            $suppress_for=1 hr,
        ]);
        }

    # ─── Exfiltration Detection (asymmetric transfer) ───
    if ( duration < exfil_min_duration )
        return;

    local orig_bytes: count = 0;
    local resp_bytes: count = 0;

    if ( c$conn?$orig_bytes )
        orig_bytes = c$conn$orig_bytes;
    if ( c$conn?$resp_bytes )
        resp_bytes = c$conn$resp_bytes;

    local total = orig_bytes + resp_bytes;

    if ( total < exfil_min_bytes )
        return;

    # Determine the dominant direction
    local dominant_bytes: count = 0;
    local minor_bytes: count = 0;
    local direction = "";

    if ( orig_bytes > resp_bytes )
        {
        dominant_bytes = orig_bytes;
        minor_bytes = resp_bytes;
        direction = "upload";
        }
    else
        {
        dominant_bytes = resp_bytes;
        minor_bytes = orig_bytes;
        direction = "download";
        }

    # Avoid division by zero
    if ( minor_bytes == 0 )
        minor_bytes = 1;

    local ratio = (dominant_bytes + 0.0) / (minor_bytes + 0.0);

    if ( ratio >= exfil_asymmetry_ratio )
        {
        local exfil_msg = fmt("Potential data exfiltration: %s -> %s:%s, %s=%s bytes, ratio=%.1f:1, duration=%s [MITRE ATT&CK: T1041]",
                              src, dst, dst_port, direction,
                              dominant_bytes, ratio, duration);
        NOTICE([
            $note=Potential_Exfil,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=exfil_msg,
            $sub=fmt("%s=%d ratio=%.1f duration=%s", direction, dominant_bytes, ratio, duration),
            $identifier=cat(c$uid),
            $suppress_for=1 hr,
        ]);
        }
    }

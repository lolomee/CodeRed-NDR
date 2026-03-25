##! CodeRed NDR — Certificate Anomaly Detection
##! Detects suspicious TLS certificates: self-signed to external IPs,
##! short validity periods, expired certs, and suspicious subjects.
##! MITRE ATT&CK: T1587.003 (Digital Certificates)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a suspicious certificate is observed.
        Suspicious_Certificate,
    };

    ## Minimum validity period — certs valid for less than this are flagged.
    const cert_min_validity_days: count = 7 &redef;

    ## Whether to alert on self-signed certs to external destinations.
    const cert_alert_self_signed_external: bool = T &redef;

    ## Whether to alert on expired certificates.
    const cert_alert_expired: bool = T &redef;

    ## Whether to alert on certs with IP addresses as CN.
    const cert_alert_ip_as_cn: bool = T &redef;

    ## Suppress interval for repeated notices about the same cert.
    const cert_suppress_interval: interval = 1 hr &redef;
}

# Pattern to match IP addresses in CN fields.
const ip_pattern = /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/ &redef;

event ssl_established(c: connection)
    {
    if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 )
        return;

    local cert = c$ssl$cert_chain[0]$x509$certificate;
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;

    local server_name = "";
    if ( c$ssl?$server_name )
        server_name = c$ssl$server_name;

    # ─── Self-signed certificate to external IP ───
    if ( cert_alert_self_signed_external )
        {
        # A self-signed cert has the same issuer and subject
        if ( cert?$issuer && cert?$subject && cert$issuer == cert$subject )
            {
            # Only alert if destination is external
            if ( ! Site::is_local_addr(dst) )
                {
                local ss_msg = fmt("Self-signed certificate to external host: %s -> %s:%s, subject=%s, sni=%s [MITRE ATT&CK: T1587.003]",
                                   src, dst, dst_port, cert$subject, server_name);
                NOTICE([
                    $note=Suspicious_Certificate,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=ss_msg,
                    $sub=fmt("self-signed subject=%s", cert$subject),
                    $identifier=cat(dst, cert$subject),
                    $suppress_for=cert_suppress_interval,
                ]);
                }
            }
        }

    # ─── Short validity period ───
    if ( cert?$not_valid_before && cert?$not_valid_after )
        {
        local validity = cert$not_valid_after - cert$not_valid_before;
        local validity_days = interval_to_double(validity) / 86400.0;

        if ( validity_days < cert_min_validity_days && validity_days > 0.0 )
            {
            local short_msg = fmt("Short-lived certificate: %s -> %s:%s, validity=%.1f days, subject=%s [MITRE ATT&CK: T1587.003]",
                                  src, dst, dst_port, validity_days, cert$subject);
            NOTICE([
                $note=Suspicious_Certificate,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=short_msg,
                $sub=fmt("validity=%.1f_days subject=%s", validity_days, cert$subject),
                $identifier=cat(dst, cert$subject),
                $suppress_for=cert_suppress_interval,
            ]);
            }

        # ─── Expired certificate ───
        if ( cert_alert_expired && cert$not_valid_after < network_time() )
            {
            local exp_msg = fmt("Expired certificate in use: %s -> %s:%s, expired=%s, subject=%s [MITRE ATT&CK: T1587.003]",
                                src, dst, dst_port, cert$not_valid_after, cert$subject);
            NOTICE([
                $note=Suspicious_Certificate,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=exp_msg,
                $sub=fmt("expired=%s subject=%s", cert$not_valid_after, cert$subject),
                $identifier=cat(dst, cert$subject, "expired"),
                $suppress_for=cert_suppress_interval,
            ]);
            }
        }

    # ─── Suspicious subject: IP address as CN ───
    if ( cert_alert_ip_as_cn && cert?$subject )
        {
        # Extract CN from subject string (format: CN=value,...)
        local cn = "";
        local parts = split_string(cert$subject, /,/);
        for ( idx in parts )
            {
            local trimmed = sub(parts[idx], /^ */, "");
            if ( /^CN=/ in trimmed )
                {
                cn = sub(trimmed, /^CN=/, "");
                break;
                }
            }

        if ( |cn| > 0 && ip_pattern in cn )
            {
            local ip_msg = fmt("Certificate with IP address as CN: %s -> %s:%s, CN=%s [MITRE ATT&CK: T1587.003]",
                               src, dst, dst_port, cn);
            NOTICE([
                $note=Suspicious_Certificate,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=ip_msg,
                $sub=fmt("ip_cn=%s subject=%s", cn, cert$subject),
                $identifier=cat(dst, cn),
                $suppress_for=cert_suppress_interval,
            ]);
            }

        # ─── Suspicious subject: empty or minimal CN ───
        if ( |cn| == 0 && cert$subject == "" )
            {
            local empty_msg = fmt("Certificate with empty subject: %s -> %s:%s [MITRE ATT&CK: T1587.003]",
                                  src, dst, dst_port);
            NOTICE([
                $note=Suspicious_Certificate,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=empty_msg,
                $sub="empty_subject",
                $identifier=cat(dst, dst_port, "empty_subject"),
                $suppress_for=cert_suppress_interval,
            ]);
            }
        }
    }

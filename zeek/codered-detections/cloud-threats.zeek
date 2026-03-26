##! CodeRed NDR — Cloud Threat Detection
##! Detects cloud-specific attacks: EC2/Azure/GCP Instance Metadata Service (IMDS)
##! abuse for credential theft, cloud storage C2 channels, SSRF attacks targeting
##! metadata endpoints, and anomalous cloud API usage from compute instances.
##!
##! This script assumes the NDR sensor is deployed INSIDE the cloud VPC/VNet
##! monitoring east-west traffic. For internet-facing detection, it also
##! monitors outbound connections to cloud metadata IPs from unexpected sources.
##!
##! MITRE ATT&CK:
##!   T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
##!   T1537    — Transfer Data to Cloud Account
##!   T1530    — Data from Cloud Storage Object
##!   T1567.002 — Exfiltration to Cloud Storage
##!   T1102    — Web Service (cloud storage as C2)
##!   T1190    — Exploit Public-Facing Application (SSRF to IMDS)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when IMDS (Instance Metadata Service) is accessed directly
        ## via the wire — indicates SSRF or container escape.
        Cloud_IMDS_Access,

        ## Raised when cloud storage services are used for C2 or exfiltration.
        Cloud_Storage_C2,

        ## Raised on anomalous cloud API calls (metadata endpoint access patterns).
        Cloud_API_Abuse,

        ## Raised when AWS/Azure/GCP credential material appears in HTTP traffic.
        Cloud_Credential_Exposure,

        ## Raised when internal hosts query cloud provider IP ranges unexpectedly.
        Cloud_Internal_Metadata_Query,
    };

    ## Cloud Instance Metadata Service IPs (link-local, non-routable).
    ## If a sensor sees traffic to these IPs, it means SSRF or container escape.
    const imds_ips: set[addr] = {
        169.254.169.254,   # AWS IMDSv1/v2, GCP metadata, Azure IMDS (shared)
        168.63.129.16,     # Azure IMDS / internal health probe
        # fd00:ec2::254 (AWS IMDSv2 IPv6) removed — Zeek addr literal syntax
        # does not support this IPv6 format in set declarations.
    } &redef;

    ## Cloud metadata service paths — requests to these paths from unexpected
    ## sources indicate SSRF attacks targeting credential theft.
    const imds_paths: set[string] = {
        "/latest/meta-data/",
        "/latest/meta-data/iam/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data",
        "/latest/dynamic/instance-identity/",
        "/metadata/v1/",                            # DigitalOcean
        "/metadata/instance",                       # Azure IMDS
        "/computeMetadata/v1/",                     # GCP
        "/computeMetadata/v1/instance/service-accounts/",  # GCP SA token
        "/opc/v1/instance/",                        # Oracle Cloud
        "/?comp=metadata",                          # Azure legacy
    } &redef;

    ## Cloud storage domains used for C2 / exfiltration.
    ## Attackers store payloads and exfil data in legitimate cloud storage.
    const cloud_storage_c2_patterns: set[string] = {
        # AWS S3 patterns (unusual subdomains or buckets)
        ".s3.amazonaws.com",
        ".s3-website",
        "s3.amazonaws.com",

        # Azure Blob Storage
        ".blob.core.windows.net",
        ".azureedge.net",

        # GCP Cloud Storage
        ".storage.googleapis.com",
        "storage.googleapis.com",

        # Generic cloud storage (often abused)
        "drive.google.com",
        "docs.google.com",
        "onedrive.live.com",
        "1drv.ms",
        "dropbox.com",
        "www.dropbox.com",
        "dl.dropboxusercontent.com",
        "mega.nz",
        "mega.co.nz",
        "cdn.discordapp.com",  # Discord CDN — popular malware hosting
        "discord.com",         # Discord webhooks as C2
        "webhook.site",        # Popular for C2 testing
        "ngrok.io",            # Tunneling service — attacker pivot
        "ngrok.com",
        "serveo.net",          # Tunneling
        "pagekite.me",         # Tunneling
    } &redef;

    ## AWS credential string patterns (access key prefixes).
    const aws_key_patterns: set[string] = {
        "AKIA",   # IAM user long-term access key
        "ASIA",   # STS temporary key
        "AROA",   # IAM role
        "AGPA",   # IAM group
        "AIDA",   # IAM user
        "ANPA",   # Managed policy
        "ANVA",   # Virtual MFA device
        "APKA",   # Public key
    } &redef;

    ## Suppress interval for cloud alerts.
    const cloud_suppress_interval: interval = 15 min &redef;

    ## Minimum upload size to flag as cloud exfiltration (50MB).
    const cloud_exfil_bytes: count = 52428800 &redef;
}

# ─── IMDS access detection ────────────────────────────────────────────────

event connection_established(c: connection)
    {
    local dst = c$id$resp_h;

    if ( dst !in imds_ips )
        return;

    local src = c$id$orig_h;
    local msg = fmt("Cloud IMDS access: %s -> %s (IMDS IP) — possible SSRF or container escape [MITRE ATT&CK: T1552.005]",
                    src, dst);
    NOTICE([$note=Cloud_IMDS_Access,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("imds_ip=%s", dst),
            $identifier=cat(src, cat(dst), "imds"),
            $suppress_for=cloud_suppress_interval]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local host = "";

    if ( c$http?$host )
        host = to_lower(c$http$host);

    local uri_lower = to_lower(original_URI);

    # ── IMDS path access via HTTP ──
    for ( ipath in imds_paths )
        {
        if ( ipath in uri_lower )
            {
            local imsg = fmt("Cloud IMDS credential path access: %s -> %s (uri=%s) [MITRE ATT&CK: T1552.005]",
                             src, dst, original_URI);
            NOTICE([$note=Cloud_IMDS_Access,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=imsg,
                    $sub=fmt("path=%s host=%s", original_URI, host),
                    $identifier=cat(src, ipath),
                    $suppress_for=cloud_suppress_interval]);
            return;
            }
        }

    # ── Cloud storage C2 / exfil via HTTP ──
    for ( storage_pattern in cloud_storage_c2_patterns )
        {
        if ( storage_pattern in host )
            {
            # Only flag uploads (PUT/POST) as exfil, GET as C2 staging
            local is_upload = ( method == "PUT" || method == "POST" );
            local tactic = is_upload ? "T1567.002" : "T1102";
            local action  = is_upload ? "upload/exfil" : "download/C2-staging";

            local smsg = fmt("Cloud storage %s: %s -> %s (host=%s method=%s) [MITRE ATT&CK: %s]",
                             action, src, dst, host, method, tactic);
            NOTICE([$note=Cloud_Storage_C2,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=smsg,
                    $sub=fmt("host=%s method=%s pattern=%s", host, method, storage_pattern),
                    $identifier=cat(src, storage_pattern, method),
                    $suppress_for=cloud_suppress_interval]);
            return;
            }
        }

    # ── GCP metadata headers (X-Google-Metadata-Request) ──
    if ( c$http?$client_header_names )
        {
        for ( idx in c$http$client_header_names )
            {
            local hdr = to_lower(c$http$client_header_names[idx]);
            if ( hdr == "metadata-flavor" || hdr == "x-aws-ec2-metadata-token" )
                {
                local hmsg = fmt("Cloud metadata header in HTTP request: %s -> %s (header=%s) [MITRE ATT&CK: T1552.005]",
                                 src, dst, hdr);
                NOTICE([$note=Cloud_API_Abuse,
                        $conn=c,
                        $src=src,
                        $dst=dst,
                        $msg=hmsg,
                        $sub=fmt("metadata_header=%s", hdr),
                        $identifier=cat(src, hdr),
                        $suppress_for=cloud_suppress_interval]);
                return;
                }
            }
        }
    }

# ─── AWS credential material in HTTP headers / responses ──────────────────

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    local value_upper = to_upper(value);

    for ( prefix in aws_key_patterns )
        {
        # AWS keys are 20 chars starting with the 4-char prefix
        if ( prefix in value_upper && |value| >= 20 )
            {
            local src = c$id$orig_h;
            local dst = c$id$resp_h;
            local dir = is_orig ? "request" : "response";
            local msg = fmt("AWS credential material in HTTP %s header: %s <-> %s (header=%s, prefix=%s) [MITRE ATT&CK: T1552.005]",
                            dir, src, dst, name, prefix);
            NOTICE([$note=Cloud_Credential_Exposure,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("header=%s key_prefix=%s dir=%s", name, prefix, dir),
                    $identifier=cat(src, dst, prefix),
                    $suppress_for=cloud_suppress_interval]);
            return;
            }
        }
    }

# ─── DNS: cloud metadata or storage C2 queries ────────────────────────────

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| == 0 )
        return;

    local query_lower = to_lower(query);

    for ( storage_pattern in cloud_storage_c2_patterns )
        {
        if ( storage_pattern in query_lower )
            {
            local src = c$id$orig_h;
            local dmsg = fmt("Cloud storage/C2 DNS query: %s queried %s (matches %s) [MITRE ATT&CK: T1102, T1567.002]",
                             src, query, storage_pattern);
            NOTICE([$note=Cloud_Storage_C2,
                    $conn=c,
                    $src=src,
                    $msg=dmsg,
                    $sub=fmt("query=%s pattern=%s", query, storage_pattern),
                    $identifier=cat(src, storage_pattern, "dns"),
                    $suppress_for=cloud_suppress_interval]);
            return;
            }
        }
    }

# ─── Large upload to cloud storage (exfiltration) ─────────────────────────

event connection_state_remove(c: connection)
    {
    if ( c$conn?$orig_bytes && c$conn$orig_bytes >= cloud_exfil_bytes )
        {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;

        if ( ! Site::is_local_addr(src) || Site::is_local_addr(dst) )
            return;

        local mb = c$conn$orig_bytes / 1048576;
        local msg = fmt("Large upload to external host (cloud exfil?): %s -> %s sent %dMB [MITRE ATT&CK: T1537, T1567]",
                        src, dst, mb);
        NOTICE([$note=Cloud_Storage_C2,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("bytes=%d mb=%d", c$conn$orig_bytes, mb),
                $identifier=cat(src, dst, "cloud_upload"),
                $suppress_for=cloud_suppress_interval]);
        }
    }

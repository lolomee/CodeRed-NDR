##! CodeRed NDR — HTTP C2 & Evasion Detection
##! Detects C2 channels hidden in HTTP/S: domain fronting (SNI vs Host mismatch),
##! malleable C2 profiles (Cobalt Strike, Covenant), suspicious user-agents from
##! LOLBins (certutil, bitsadmin, mshta), fast-flux DNS, and DNS-over-HTTPS
##! used to bypass DNS monitoring.
##!
##! MITRE ATT&CK:
##!   T1071.001 — Application Layer Protocol: Web Protocols
##!   T1090.004 — Proxy: Domain Fronting
##!   T1568.003 — Dynamic Resolution: Fast Flux DNS
##!   T1218     — System Binary Proxy Execution (LOLBins)
##!   T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
##!   T1020     — Automated Exfiltration

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when TLS SNI and HTTP Host header differ — domain fronting.
        HTTP_DomainFronting,
        ## Raised on HTTP C2 user-agent patterns from LOLBins or known C2 frameworks.
        HTTP_C2_UserAgent,
        ## Raised when fast-flux DNS behavior is detected (many IPs for one domain).
        HTTP_FastFlux_DNS,
        ## Raised when DNS-over-HTTPS to non-approved resolvers is detected.
        HTTP_DoH_Bypass,
        ## Raised on HTTP request patterns matching known malleable C2 profiles.
        HTTP_MalleableC2,
    };

    ## LOLBin user-agents seen in C2/download attacks.
    ## These Windows built-in tools are abused for payload staging.
    const lolbin_user_agents: table[string] of string = {
        ["microsoft bits"]    = "BITSAdmin (T1197)",
        ["microsoft-cryptoapi"] = "CertUtil (T1553.004)",
        ["microsoft url"]     = "XMLHTTP/WinHTTP (certutil/wscript)",
        ["winhttp"]           = "WinHTTP (LOLBin staging)",
        ["mshta"]             = "MSHTA (T1218.005)",
        ["powershell"]        = "PowerShell web client (T1059.001)",
        ["python-requests"]   = "Python requests (scripted staging)",
        ["go-http-client"]    = "Go HTTP client (common in malware/C2)",
        ["ruby"]              = "Ruby HTTP (scripted attack)",
        ["curl/"]             = "curl (scripted — verify context)",
        ["wget/"]             = "wget (scripted — verify context)",
        ["masscan"]           = "Masscan scanner",
        ["zgrab"]             = "ZGrab scanner",
        ["nmap scripting"]    = "Nmap scripting engine",
        ["sqlmap"]            = "SQLMap",
        ["nuclei"]            = "Nuclei scanner",
        ["dirbuster"]         = "DirBuster",
        ["nikto"]             = "Nikto web scanner",
        ["hydra"]             = "Hydra brute force",
        ["havij"]             = "Havij SQLi tool",
        # Cobalt Strike default profiles
        ["mozilla/5.0 (windows nt 6.1"] = "Cobalt Strike default (IE7 UA)",
        ["mozilla/4.0 (compatible; msie 8.0"] = "Cobalt Strike IE8 profile",
        # Metasploit reverse_http
        ["mozilla/5.0 (x11; linux x86_64) applewebkit"] = "Metasploit UA (Linux)",
        # Empty / minimal UA — almost always malware or script
        [""]                  = "Empty user-agent (likely malware/script)",
    } &redef;

    ## Approved DNS-over-HTTPS resolvers (corporate-managed).
    ## Queries to DoH resolvers NOT in this list are flagged.
    ## Populate via redef in local.zeek.
    const approved_doh_resolvers: set[string] = {
        "dns.google",
        "cloudflare-dns.com",
        "dns.quad9.net",
    } &redef;

    ## Known DoH resolver paths — HTTP requests to these paths are DoH traffic.
    const doh_paths: set[string] = {
        "/dns-query",
        "/resolve",
        "/dns",
    } &redef;

    ## DoH resolver domains — unapproved ones bypass your DNS monitoring.
    const unapproved_doh_domains: set[string] = {
        "doh.opendns.com",
        "doh.cleanbrowsing.org",
        "doh.appliedprivacy.net",
        "dns.nextdns.io",
        "odvr.nic.cz",
        "dnsnl.alekberg.net",
        "dns10.quad9.net",
        "doh.xfinity.com",
        "dns.alidns.com",        # Alibaba DoH — common in Asian APT
        "sm2.doh.pub",           # Chinese DoH
        "doh.360.cn",            # 360 DoH
    } &redef;

    ## Known Cobalt Strike malleable C2 URI patterns.
    ## These are the default GET/POST URIs in common CS profiles.
    const cobalt_strike_uris: set[string] = {
        "/updates",
        "/update",
        "/pixel.gif",
        "/jquery-3.3.1.min.js",
        "/jquery-3.3.2.min.js",
        "/dpixel",
        "/__utm.gif",
        "/ca",
        "/image/",
        "/ga.js",
        "/ptj",
        "/j.ad",
        "/fwlink",
        "/en_us/all.js",
        "/us/all.js",
        "/activity",
        "/post.php",
        "/submit.php",
        "/login",
        "/load",
        "/push",
        "/receive",
        "/poll",
        "/results",
    } &redef;

    ## Unique IP count for a domain within the window that suggests fast flux.
    const fastflux_ip_threshold: double = 5.0 &redef;
    const fastflux_window: interval = 5 min &redef;

    ## Suppress interval.
    const http_c2_suppress_interval: interval = 15 min &redef;
}

# Track domain->IPs for fast flux detection
global domain_ips: table[string] of set[addr] &create_expire=5 min;

event zeek_init()
    {
    local r = SumStats::Reducer($stream="codered.http.domain_ips", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.http.fastflux",
        $epoch=fastflux_window,
        $reducers=set(r),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.http.domain_ips"]$unique + 0.0; },
        $threshold=fastflux_ip_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.http.domain_ips"]$unique;
            local msg = fmt("Fast-flux DNS: domain %s resolved to %d unique IPs in %s [MITRE ATT&CK: T1568.003]",
                            key$str, n, fastflux_window);
            NOTICE([$note=HTTP_FastFlux_DNS,
                    $msg=msg,
                    $sub=fmt("domain=%s unique_ips=%d", key$str, n),
                    $identifier=cat(key$str, "fastflux"),
                    $suppress_for=http_c2_suppress_interval]);
            }
    ]);
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    if ( msg?$query && |msg$query| > 0 )
        {
        SumStats::observe("codered.http.domain_ips",
                          SumStats::Key($str=msg$query),
                          SumStats::Observation($str=cat(a)));
        }
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    local uri_lower  = to_lower(original_URI);
    local host_lower = "";
    if ( c$http?$host )
        host_lower = to_lower(c$http$host);

    # ── Domain Fronting: SNI vs Host header mismatch ──
    if ( c$ssl?$server_name && |host_lower| > 0 )
        {
        local sni = to_lower(c$ssl$server_name);
        # Extract base domains for comparison (last 2 labels)
        local sni_parts  = split_string(sni, /\./);
        local host_parts = split_string(host_lower, /\./);

        local sni_base  = |sni_parts| >= 2 ?
            fmt("%s.%s", sni_parts[|sni_parts|-2], sni_parts[|sni_parts|-1]) : sni;
        local host_base = |host_parts| >= 2 ?
            fmt("%s.%s", host_parts[|host_parts|-2], host_parts[|host_parts|-1]) : host_lower;

        if ( sni_base != host_base && |sni_base| > 0 && |host_base| > 0 )
            {
            local df_msg = fmt("Domain fronting: SNI=%s but Host=%s (src=%s) [MITRE ATT&CK: T1090.004]",
                               sni, host_lower, src);
            NOTICE([$note=HTTP_DomainFronting,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=df_msg,
                    $sub=fmt("sni=%s host=%s", sni, host_lower),
                    $identifier=cat(src, sni, host_lower),
                    $suppress_for=http_c2_suppress_interval]);
            }
        }

    # ── User-agent based LOLBin / C2 detection ──
    local ua = "";
    if ( c$http?$user_agent )
        ua = to_lower(c$http$user_agent);

    for ( pattern in lolbin_user_agents )
        {
        if ( ( |pattern| == 0 && |ua| == 0 ) ||
             ( |pattern| > 0 && pattern in ua ) )
            {
            local tool = lolbin_user_agents[pattern];
            local ua_msg = fmt("Suspicious HTTP user-agent (%s): %s -> %s (ua=%s) [MITRE ATT&CK: T1218, T1071.001]",
                               tool, src, dst, c$http$user_agent);
            NOTICE([$note=HTTP_C2_UserAgent,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=ua_msg,
                    $sub=fmt("ua=%s tool=%s", ua, tool),
                    $identifier=cat(src, pattern),
                    $suppress_for=http_c2_suppress_interval]);
            break;
            }
        }

    # ── Malleable C2 URI pattern ──
    for ( cs_uri in cobalt_strike_uris )
        {
        if ( cs_uri == uri_lower || ( |uri_lower| > |cs_uri| &&
             uri_lower[0:|cs_uri|] == cs_uri ) )
            {
            # Only flag if external destination
            if ( ! Site::is_local_addr(dst) )
                {
                local cs_msg = fmt("Malleable C2 URI pattern: %s -> %s (uri=%s) [MITRE ATT&CK: T1071.001]",
                                   src, dst, original_URI);
                NOTICE([$note=HTTP_MalleableC2,
                        $conn=c,
                        $src=src,
                        $dst=dst,
                        $msg=cs_msg,
                        $sub=fmt("uri=%s host=%s", original_URI, host_lower),
                        $identifier=cat(src, dst, cs_uri),
                        $suppress_for=http_c2_suppress_interval]);
                break;
                }
            }
        }

    # ── DNS-over-HTTPS bypass detection ──
    local uri_is_doh = F;
    for ( dp in doh_paths )
        {
        if ( dp in uri_lower )
            { uri_is_doh = T; break; }
        }

    if ( uri_is_doh || ( method == "GET" && "dns=" in uri_lower ) )
        {
        local is_approved = F;
        for ( approved in approved_doh_resolvers )
            {
            if ( approved in host_lower )
                { is_approved = T; break; }
            }

        if ( ! is_approved )
            {
            local doh_msg = fmt("DNS-over-HTTPS to unapproved resolver: %s -> %s (host=%s uri=%s) [MITRE ATT&CK: T1071.004]",
                                src, dst, host_lower, original_URI);
            NOTICE([$note=HTTP_DoH_Bypass,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=doh_msg,
                    $sub=fmt("doh_host=%s", host_lower),
                    $identifier=cat(src, host_lower, "doh"),
                    $suppress_for=http_c2_suppress_interval]);
            }
        }

    # ── Known unapproved DoH domains via host header ──
    for ( doh_dom in unapproved_doh_domains )
        {
        if ( doh_dom in host_lower )
            {
            local udoh_msg = fmt("DNS-over-HTTPS to unapproved resolver: %s -> %s (host=%s) [MITRE ATT&CK: T1071.004]",
                                 src, dst, host_lower);
            NOTICE([$note=HTTP_DoH_Bypass,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=udoh_msg,
                    $sub=fmt("unapproved_doh=%s", doh_dom),
                    $identifier=cat(src, doh_dom),
                    $suppress_for=http_c2_suppress_interval]);
            break;
            }
        }
    }

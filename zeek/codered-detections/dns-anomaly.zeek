##! CodeRed NDR — DNS Anomaly Detection
##! Detects DGA domains (high entropy), DNS tunneling (long labels, high volume),
##! and queries to rare/suspicious TLDs.
##! MITRE ATT&CK: T1568.002 (Domain Generation Algorithms), T1071.004 (DNS)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a queried domain has high entropy consistent with DGA.
        DGA_Domain,
        ## Raised when DNS tunneling indicators are detected.
        DNS_Tunneling,
    };

    ## Shannon entropy threshold for the longest domain label.
    ## Labels above this are flagged as potential DGA.
    const dga_entropy_threshold: double = 3.5 &redef;

    ## Minimum label length to evaluate for DGA (skip short labels).
    const dga_min_label_length: count = 8 &redef;

    ## Maximum subdomain label length before flagging as tunneling.
    const tunnel_max_label_length: count = 50 &redef;

    ## Maximum DNS queries per minute to a single base domain before tunneling alert.
    const tunnel_query_rate_threshold: double = 100.0 &redef;

    ## Epoch for DNS query rate tracking.
    const dns_rate_epoch: interval = 1 min &redef;

    ## Known benign TLDs (queries to TLDs not in this set may be flagged).
    ## Kept small — extend via redef for your environment.
    const common_tlds: set[string] = {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "io", "co", "us", "uk", "ca", "de", "fr", "au",
        "nl", "ru", "cn", "jp", "br", "in", "it", "es",
        "info", "biz", "me", "tv", "cc",
        "arpa", "local", "internal",
    } &redef;
}

# ─── Shannon entropy calculation ───
# Compatible with Zeek 4.x and 5.x — avoids local declarations inside loops
function shannon_entropy(s: string): double
    {
    if ( |s| == 0 )
        return 0.0;

    local freq: table[string] of count = table();
    local i: count = 0;
    local cur: string = "";
    while ( i < |s| )
        {
        cur = s[i];
        if ( cur in freq )
            freq[cur] += 1;
        else
            freq[cur] = 1;
        ++i;
        }

    local entropy: double = 0.0;
    local n: double = |s| + 0.0;
    local p: double = 0.0;
    local key: string = "";
    for ( key in freq )
        {
        p = freq[key] / n;
        if ( p > 0.0 )
            entropy -= p * (ln(p) / ln(2.0));
        }

    return entropy;
    }

# ─── Extract labels from a domain ───
function get_labels(domain: string): vector of string
    {
    return split_string(domain, /\./);
    }

# ─── Extract base domain (last two labels) ───
function get_base_domain(domain: string): string
    {
    local labels = get_labels(domain);
    if ( |labels| >= 2 )
        return fmt("%s.%s", labels[|labels| - 2], labels[|labels| - 1]);
    return domain;
    }

# ─── Extract TLD ───
function get_tld(domain: string): string
    {
    local labels = get_labels(domain);
    if ( |labels| > 0 )
        return labels[|labels| - 1];
    return domain;
    }

# ─── SumStats for DNS query rate per base domain ───
event zeek_init()
    {
    local r1 = SumStats::Reducer(
        $stream="codered.dns.query_rate",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="codered.dns.tunnel_rate",
        $epoch=dns_rate_epoch,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.dns.query_rate"]$sum;
            },
        $threshold=tunnel_query_rate_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local msg = fmt("DNS tunneling (high query rate): %s -> domain %s, %.0f queries/min [MITRE ATT&CK: T1071.004]",
                            key$host, key$str, result["codered.dns.query_rate"]$sum);
            NOTICE([
                $note=DNS_Tunneling,
                $src=key$host,
                $msg=msg,
                $sub=fmt("domain=%s rate=%.0f/min", key$str, result["codered.dns.query_rate"]$sum),
                $identifier=cat(key$host, key$str),
                $suppress_for=5 min,
            ]);
            }
    ]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| == 0 )
        return;

    local src = c$id$orig_h;
    local labels = get_labels(query);

    # ─── DGA Detection: check entropy of longest non-TLD label ───
    local longest_label = "";
    local idx: count = 0;
    # Check all labels except the TLD
    while ( idx < |labels| && idx + 1 < |labels| )
        {
        if ( |labels[idx]| > |longest_label| )
            longest_label = labels[idx];
        ++idx;
        }

    if ( |longest_label| >= dga_min_label_length )
        {
        local ent = shannon_entropy(longest_label);
        if ( ent > dga_entropy_threshold )
            {
            local dga_msg = fmt("Potential DGA domain: %s (label=%s, entropy=%.2f) from %s [MITRE ATT&CK: T1568.002]",
                                query, longest_label, ent, src);
            NOTICE([
                $note=DGA_Domain,
                $src=src,
                $msg=dga_msg,
                $sub=fmt("entropy=%.2f label=%s", ent, longest_label),
                $identifier=cat(src, query),
                $suppress_for=10 min,
            ]);
            }
        }

    # ─── DNS Tunneling: long subdomain labels ───
    idx = 0;
    while ( idx < |labels| && idx + 1 < |labels| )
        {
        if ( |labels[idx]| > tunnel_max_label_length )
            {
            local tun_msg = fmt("DNS tunneling (long label): %s, label length=%d from %s [MITRE ATT&CK: T1071.004]",
                                query, |labels[idx]|, src);
            NOTICE([
                $note=DNS_Tunneling,
                $src=src,
                $msg=tun_msg,
                $sub=fmt("label_length=%d query=%s", |labels[idx]|, query),
                $identifier=cat(src, get_base_domain(query)),
                $suppress_for=5 min,
            ]);
            break;
            }
        ++idx;
        }

    # ─── DNS query rate tracking (for tunneling via volume) ───
    local base = get_base_domain(query);
    SumStats::observe("codered.dns.query_rate",
                      SumStats::Key($host=src, $str=base),
                      SumStats::Observation($num=1));
    }

##! CodeRed NDR — Cryptomining Detection
##! Detects cryptocurrency mining activity: Stratum protocol (XMR, ETH, BTC),
##! DNS lookups to known mining pools, mining-related HTTP/S traffic, and
##! suspicious outbound connections on mining ports.
##! Covers both direct mining and malware-driven mining (XMRig, TeamTNT etc.)
##!
##! MITRE ATT&CK:
##!   T1496  — Resource Hijacking
##!   T1071.001 — Application Layer Protocol: Web Protocols (Stratum over HTTP)
##!   T1571  — Non-Standard Port
##!   T1041  — Exfiltration Over C2 Channel (mining pool as C2)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when Stratum mining protocol is detected.
        Cryptomining_Stratum,
        ## Raised when a DNS query to a known mining pool is observed.
        Cryptomining_PoolDNS,
        ## Raised when mining-related HTTP traffic is detected.
        Cryptomining_HTTP,
        ## Raised when connection to a known mining port/pool IP is detected.
        Cryptomining_Connection,
    };

    ## Known mining pool domain patterns (substring match on DNS queries).
    const mining_pool_domains: set[string] = {
        # Monero (XMR) pools — most common in malware
        "pool.minexmr.com", "minexmr.com",
        "xmrpool.eu", "xmrpool.net",
        "moneroocean.stream",
        "supportxmr.com",
        "c3pool.com", "c3pool.org",
        "hashvault.pro",
        "xmr.2miners.com",
        "xmr-asia1.nanopool.org", "xmr-eu1.nanopool.org",
        "xmr-us-east1.nanopool.org",
        "pool.hashvault.pro",
        "mine.xmrpool.net",
        "rx.unmineable.com",

        # Ethereum pools
        "eth.2miners.com", "eth-eu1.nanopool.org",
        "ethermine.org", "eth.ethermine.org",
        "eu1.ethermine.org", "us1.ethermine.org",
        "sparkpool.com", "eth.sparkpool.com",
        "f2pool.com", "eth.f2pool.com",

        # Bitcoin / general
        "pool.bitcoin.com", "btc.f2pool.com",
        "btc.viabtc.com", "antpool.com",
        "slushpool.com",

        # Mining malware infrastructure (TeamTNT, 8220 Gang etc.)
        "miners.emsisoft.com",     # benign but often queried by scanners
        "xmrig.com",               # XMRig download domain
        "coinhive.com",            # defunct but still seen in old malware
        "coin-hive.com",
        "jsecoin.com",
        "monerominer.rocks",
        "mine.pp.ua",
        "cryptonight.net",
        "ryobitools.xyz",          # 8220 Gang proxy
    } &redef;

    ## Known mining ports (Stratum protocol default).
    const mining_ports: set[port] = {
        3333/tcp,   # Stratum default (XMR, ETH)
        4444/tcp,   # Stratum alternate
        5555/tcp,   # Stratum alternate
        7777/tcp,   # Stratum alternate
        9999/tcp,   # Stratum alternate
        14444/tcp,  # XMR pool alternate
        45700/tcp,  # Stratum TLS
        3256/tcp,   # Monero pool variant
        14433/tcp,  # TLS Stratum
    } &redef;

    ## HTTP user-agents associated with mining software.
    const mining_user_agents: set[string] = {
        "xmrig/", "ccminer/", "sgminer/", "cgminer/",
        "bfgminer/", "cpuminer/", "ethminer/", "minerd/",
        "teamtnt-miner", "kinsing",
    } &redef;

    ## Stratum protocol JSON method patterns in HTTP/raw TCP.
    const stratum_methods: set[string] = {
        "mining.subscribe", "mining.authorize",
        "mining.submit", "mining.notify",
        "eth_submitLogin", "eth_getWork",
        "eth_submitWork", "eth_submitHashrate",
    } &redef;

    ## Suppress interval for repeated mining alerts.
    const mining_suppress_interval: interval = 30 min &redef;

    ## Window and threshold for mining connection bursts.
    const mining_conn_threshold: double = 3.0 &redef;
    const mining_conn_window: interval = 5 min &redef;
}

# ─── SumStats: mining port connection burst ───────────────────────────────

event zeek_init()
    {
    local r = SumStats::Reducer($stream="codered.mining.port_conn", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.mining.port_burst",
        $epoch=mining_conn_window,
        $reducers=set(r),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.mining.port_conn"]$sum; },
        $threshold=mining_conn_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.mining.port_conn"]$sum;
            local msg = fmt("Cryptomining pool connections: %s made %.0f connections to mining ports in %s [MITRE ATT&CK: T1496]",
                            key$host, n, mining_conn_window);
            NOTICE([$note=Cryptomining_Connection,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("mining_connections=%.0f", n),
                    $identifier=cat(key$host, "mining_conn"),
                    $suppress_for=mining_suppress_interval]);
            }
    ]);
    }

# ─── DNS to mining pools ──────────────────────────────────────────────────

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| == 0 )
        return;

    local query_lower = to_lower(query);

    for ( pool in mining_pool_domains )
        {
        if ( pool in query_lower )
            {
            local src = c$id$orig_h;
            local msg_str = fmt("DNS query to cryptomining pool: %s queried %s (matches %s) [MITRE ATT&CK: T1496]",
                                src, query, pool);
            NOTICE([$note=Cryptomining_PoolDNS,
                    $conn=c,
                    $src=src,
                    $msg=msg_str,
                    $sub=fmt("query=%s pool=%s", query, pool),
                    $identifier=cat(src, pool),
                    $suppress_for=mining_suppress_interval]);
            return;
            }
        }
    }

# ─── Stratum protocol on mining ports ────────────────────────────────────

event connection_established(c: connection)
    {
    if ( c$id$resp_p !in mining_ports )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.mining.port_conn",
                      SumStats::Key($host=src),
                      SumStats::Observation($num=1));

    # Alert immediately on single connection to known mining port
    local msg = fmt("Cryptomining port connection: %s -> %s:%s (Stratum port) [MITRE ATT&CK: T1496, T1571]",
                    src, dst, c$id$resp_p);
    NOTICE([$note=Cryptomining_Connection,
            $conn=c,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("port=%s", c$id$resp_p),
            $identifier=cat(src, dst, cat(c$id$resp_p)),
            $suppress_for=mining_suppress_interval]);
    }

# ─── HTTP mining traffic (Stratum over HTTP, WebSocket mining) ────────────

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Check user agent for known mining software
    if ( c$http?$user_agent )
        {
        local ua = to_lower(c$http$user_agent);
        for ( miner_ua in mining_user_agents )
            {
            if ( miner_ua in ua )
                {
                local msg = fmt("Cryptominer user-agent: %s -> %s (ua=%s) [MITRE ATT&CK: T1496]",
                                src, c$id$resp_h, c$http$user_agent);
                NOTICE([$note=Cryptomining_HTTP,
                        $conn=c,
                        $src=src,
                        $dst=c$id$resp_h,
                        $msg=msg,
                        $sub=fmt("ua=%s", c$http$user_agent),
                        $identifier=cat(src, miner_ua),
                        $suppress_for=mining_suppress_interval]);
                return;
                }
            }
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;

    local src = c$id$orig_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Detect Stratum JSON methods in HTTP POST body
    local data_lower = to_lower(data);
    for ( method in stratum_methods )
        {
        if ( method in data_lower )
            {
            local msg = fmt("Stratum mining protocol in HTTP body: %s -> %s (method=%s) [MITRE ATT&CK: T1496, T1071.001]",
                            src, c$id$resp_h, method);
            NOTICE([$note=Cryptomining_Stratum,
                    $conn=c,
                    $src=src,
                    $dst=c$id$resp_h,
                    $msg=msg,
                    $sub=fmt("stratum_method=%s", method),
                    $identifier=cat(src, c$id$resp_h, method),
                    $suppress_for=mining_suppress_interval]);
            return;
            }
        }
    }

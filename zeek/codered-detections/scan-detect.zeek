##! CodeRed NDR — Enhanced Scan Detection
##! Detects port scans (single source, many ports on one destination)
##! and network sweeps (single source, many destinations on same port).
##! MITRE ATT&CK: T1046 (Network Service Discovery)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a host scans multiple ports on a single destination.
        Port_Scan,
        ## Raised when a host sweeps multiple destinations on the same port.
        Network_Sweep,
    };

    ## Number of unique ports on a single destination to trigger a port scan alert.
    const scan_port_threshold: double = 20.0 &redef;

    ## Number of unique destinations on the same port to trigger a sweep alert.
    const sweep_host_threshold: double = 15.0 &redef;

    ## Time window for scan/sweep detection.
    const scan_window: interval = 5 min &redef;
}

event zeek_init()
    {
    # ─── Port Scan: track unique ports per (src, dst) pair ───
    local r_port = SumStats::Reducer(
        $stream="codered.scan.ports",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="codered.scan.port_scan",
        $epoch=scan_window,
        $reducers=set(r_port),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.scan.ports"]$unique + 0.0;
            },
        $threshold=scan_port_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local unique_ports = result["codered.scan.ports"]$unique;
            local msg = fmt("Port scan detected: %s -> %s, %d unique ports in %s [MITRE ATT&CK: T1046]",
                            key$host, key$str, unique_ports, scan_window);
            NOTICE([
                $note=Port_Scan,
                $src=key$host,
                $msg=msg,
                $sub=fmt("target=%s unique_ports=%d", key$str, unique_ports),
                $identifier=cat(key$host, key$str),
                $suppress_for=scan_window,
            ]);
            }
    ]);

    # ─── Network Sweep: track unique destinations per (src, port) pair ───
    local r_sweep = SumStats::Reducer(
        $stream="codered.scan.sweep",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="codered.scan.network_sweep",
        $epoch=scan_window,
        $reducers=set(r_sweep),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.scan.sweep"]$unique + 0.0;
            },
        $threshold=sweep_host_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local unique_hosts = result["codered.scan.sweep"]$unique;
            local msg = fmt("Network sweep detected: %s scanning port %s, %d unique destinations in %s [MITRE ATT&CK: T1046]",
                            key$host, key$str, unique_hosts, scan_window);
            NOTICE([
                $note=Network_Sweep,
                $src=key$host,
                $msg=msg,
                $sub=fmt("port=%s unique_hosts=%d", key$str, unique_hosts),
                $identifier=cat(key$host, key$str),
                $suppress_for=scan_window,
            ]);
            }
    ]);
    }

event connection_attempt(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;

    # ─── Port Scan observation: key=(src, dst), observe=port ───
    SumStats::observe("codered.scan.ports",
                      SumStats::Key($host=src, $str=cat(dst)),
                      SumStats::Observation($str=cat(dst_port)));

    # ─── Network Sweep observation: key=(src, port), observe=dst ───
    SumStats::observe("codered.scan.sweep",
                      SumStats::Key($host=src, $str=cat(dst_port)),
                      SumStats::Observation($str=cat(dst)));
    }

# Also track successful connections (not just SYN-only)
event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dst_port = c$id$resp_p;

    SumStats::observe("codered.scan.ports",
                      SumStats::Key($host=src, $str=cat(dst)),
                      SumStats::Observation($str=cat(dst_port)));

    SumStats::observe("codered.scan.sweep",
                      SumStats::Key($host=src, $str=cat(dst_port)),
                      SumStats::Observation($str=cat(dst)));
    }

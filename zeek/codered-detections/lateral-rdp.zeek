##! CodeRed NDR — RDP Lateral Movement Detection
##! Detects RDP-based lateral movement: brute force login attempts,
##! credential spraying across multiple targets, and RDP from unusual
##! internal sources (workstation-to-workstation RDP).
##!
##! MITRE ATT&CK:
##!   T1021.001 — Remote Services: Remote Desktop Protocol
##!   T1110.001 — Brute Force: Password Guessing
##!   T1110.003 — Brute Force: Password Spraying

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a source makes many failed RDP connections to a single target.
        RDP_BruteForce,

        ## Raised when a source attempts RDP to many unique internal hosts (spray).
        RDP_Spray,

        ## Raised when a workstation initiates RDP to another workstation
        ## (unusual — workstations don't normally RDP to each other).
        RDP_LateralHop,
    };

    ## Standard RDP port.
    const rdp_port: port = 3389/tcp &redef;

    ## Additional non-standard RDP ports to monitor (port-forwarded RDP).
    const rdp_alt_ports: set[port] = {
        3390/tcp, 3391/tcp, 3392/tcp,
        33890/tcp, 33891/tcp,
        13389/tcp,
    } &redef;

    ## Failed RDP connection threshold against a single target.
    ## A failed RDP connection is a TCP SYN with no full handshake or
    ## a very short-lived session (< 5 seconds).
    const rdp_brute_threshold: double = 8.0 &redef;

    ## Number of unique RDP targets from a single source to trigger spray alert.
    const rdp_spray_threshold: double = 5.0 &redef;

    ## Time window for RDP brute force and spray detection.
    const rdp_detect_window: interval = 3 min &redef;

    ## Minimum session duration (seconds). Sessions shorter than this
    ## to an RDP port are treated as failed/rejected connections.
    const rdp_min_session_duration: interval = 5 sec &redef;

    ## Suppress repeat notices per source.
    const rdp_suppress_interval: interval = 10 min &redef;

    ## Known RDP jump server/bastion IPs — suppress LateralHop alerts for these.
    const rdp_jump_servers: set[addr] = {} &redef;
}

# ─── Helper: check if a port is an RDP port ──────────────────────────────

function is_rdp_port(p: port): bool
    {
    if ( p == rdp_port )
        return T;
    if ( p in rdp_alt_ports )
        return T;
    return F;
    }

# ─── SumStats setup ───────────────────────────────────────────────────────

event zeek_init()
    {
    # ── Brute force: count short/failed RDP sessions per (src, dst) pair ──
    local r_brute = SumStats::Reducer(
        $stream="codered.rdp.fail",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name="codered.rdp.bruteforce",
        $epoch=rdp_detect_window,
        $reducers=set(r_brute),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.rdp.fail"]$sum;
            },
        $threshold=rdp_brute_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local fails = result["codered.rdp.fail"]$sum;
            # key$host = src, key$str = dst
            local msg = fmt("RDP brute force: %s -> %s, %.0f failed attempts in %s [MITRE ATT&CK: T1110.001, T1021.001]",
                            key$host, key$str, fails, rdp_detect_window);
            NOTICE([$note=RDP_BruteForce,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("target=%s fails=%.0f", key$str, fails),
                    $identifier=cat(key$host, key$str, "rdp_brute"),
                    $suppress_for=rdp_suppress_interval]);
            }
    ]);

    # ── Spray: count unique RDP targets per source ──
    local r_spray = SumStats::Reducer(
        $stream="codered.rdp.targets",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="codered.rdp.spray",
        $epoch=rdp_detect_window,
        $reducers=set(r_spray),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            {
            return result["codered.rdp.targets"]$unique + 0.0;
            },
        $threshold=rdp_spray_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local unique_targets = result["codered.rdp.targets"]$unique;
            local msg = fmt("RDP credential spray: %s attempted RDP to %d unique hosts in %s [MITRE ATT&CK: T1110.003, T1021.001]",
                            key$host, unique_targets, rdp_detect_window);
            NOTICE([$note=RDP_Spray,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_targets=%d window=%s", unique_targets, rdp_detect_window),
                    $identifier=cat(key$host, "rdp_spray"),
                    $suppress_for=rdp_suppress_interval]);
            }
    ]);
    }

# ─── Connection state removal: evaluate completed/terminated sessions ──────

event connection_state_remove(c: connection)
    {
    if ( ! is_rdp_port(c$id$resp_p) )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Only care about internal sources
    if ( ! Site::is_local_addr(src) )
        return;

    local duration = c$duration;

    # ── Short / failed session = likely rejected auth ──
    # A successful RDP session typically lasts > 5 seconds.
    # SYN-only or NullSession attempts are very short.
    if ( duration < rdp_min_session_duration )
        {
        SumStats::observe("codered.rdp.fail",
                          SumStats::Key($host=src, $str=cat(dst)),
                          SumStats::Observation($num=1));
        }

    # ── Always track unique targets for spray detection ──
    SumStats::observe("codered.rdp.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));

    # ── Workstation-to-workstation RDP (lateral hop) ──
    # Heuristic: both ends are internal, source is NOT a known jump server,
    # and the session was long enough to actually be used (> 5s).
    if ( Site::is_local_addr(dst) &&
         src !in rdp_jump_servers &&
         dst !in rdp_jump_servers &&
         duration >= rdp_min_session_duration )
        {
        # Check if source looks like a workstation:
        # The site-local heuristic is imperfect. Analysts can tune
        # rdp_jump_servers to suppress false positives for jump boxes.
        local msg = fmt("RDP lateral hop (workstation->workstation): %s -> %s, duration=%s [MITRE ATT&CK: T1021.001]",
                        src, dst, duration);
        NOTICE([$note=RDP_LateralHop,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("duration=%s rdp_port=%s", duration, c$id$resp_p),
                $identifier=cat(src, dst, "rdp_hop"),
                $suppress_for=rdp_suppress_interval]);
        }
    }

# ─── Log new RDP connections for spray tracking ───────────────────────────

event connection_established(c: connection)
    {
    if ( ! is_rdp_port(c$id$resp_p) )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Observe target immediately on connection attempt (covers SYN-only scans)
    SumStats::observe("codered.rdp.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));
    }

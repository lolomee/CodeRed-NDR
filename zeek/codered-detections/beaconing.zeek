##! CodeRed NDR — Beaconing Detection
##! Detects C2 beaconing patterns by tracking connection intervals
##! between source-destination pairs and flagging regular timing.
##! MITRE ATT&CK: T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a host shows regular beaconing behavior to a destination.
        Beaconing_Detected,
    };

    ## Minimum number of connections in the window to evaluate beaconing.
    const beaconing_min_connections: count = 10 &redef;

    ## Maximum jitter ratio (0.0–1.0) for intervals to be considered regular.
    ## 0.15 = 15% deviation from the mean interval.
    const beaconing_max_jitter: double = 0.15 &redef;

    ## Sliding window duration for tracking connection intervals.
    const beaconing_window: interval = 1 hr &redef;

    ## Epoch length for the SumStats reducer (should match the window).
    const beaconing_epoch: interval = 1 hr &redef;
}

# Track timestamps of connections per src-dst pair.
global beacon_tracker: table[addr, addr] of vector of time &create_expire=1 hr;

event connection_state_remove(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Skip local-to-local if both are private (optional tuning point)
    if ( Site::is_local_addr(src) && Site::is_local_addr(dst) )
        return;

    # Only track outbound from local network
    if ( ! Site::is_local_addr(src) )
        return;

    if ( [src, dst] !in beacon_tracker )
        beacon_tracker[src, dst] = vector();

    beacon_tracker[src, dst] += network_time();

    local timestamps = beacon_tracker[src, dst];

    if ( |timestamps| < beaconing_min_connections )
        return;

    # Compute intervals between consecutive connections
    local intervals: vector of double = vector();
    local i: count = 1;
    while ( i < |timestamps| )
        {
        local delta = interval_to_double(timestamps[i] - timestamps[i - 1]);
        if ( delta > 0.0 )
            intervals += delta;
        ++i;
        }

    if ( |intervals| < beaconing_min_connections - 1 )
        return;

    # Compute mean interval
    local sum: double = 0.0;
    for ( idx in intervals )
        sum += intervals[idx];
    local mean = sum / |intervals|;

    # Skip if mean is essentially zero (burst traffic, not beaconing)
    if ( mean < 1.0 )
        return;

    # Compute standard deviation
    local var_sum: double = 0.0;
    for ( idx in intervals )
        {
        local diff = intervals[idx] - mean;
        var_sum += diff * diff;
        }
    local stddev = sqrt(var_sum / |intervals|);

    # Jitter ratio = coefficient of variation
    local jitter_ratio = stddev / mean;

    if ( jitter_ratio < beaconing_max_jitter )
        {
        local msg = fmt("Potential C2 beaconing: %s -> %s, %d connections, interval=%.1fs, jitter=%.1f%% [MITRE ATT&CK: T1071, T1573]",
                        src, dst, |timestamps|, mean, jitter_ratio * 100.0);

        NOTICE([
            $note=Beaconing_Detected,
            $src=src,
            $dst=dst,
            $msg=msg,
            $sub=fmt("interval=%.1fs jitter=%.1f%%", mean, jitter_ratio * 100.0),
            $identifier=cat(src, dst),
            $suppress_for=beaconing_window,
        ]);

        # Reset tracker for this pair after alerting
        delete beacon_tracker[src, dst];
        }
    }

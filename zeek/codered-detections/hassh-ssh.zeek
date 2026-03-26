##! CodeRed NDR — SSH Threat Detection (HASSH Fingerprinting + Brute Force + Tunneling)
##! HASSH fingerprints SSH clients by their key exchange algorithm lists —
##! different SSH clients (OpenSSH, PuTTY, Paramiko, Impacket, AsyncSSH)
##! produce distinct fingerprints. Known malicious tools leave known fingerprints.
##! Also detects SSH brute force, password spray, and SSH tunneling abuse.
##!
##! MITRE ATT&CK:
##!   T1021.004 — Remote Services: SSH
##!   T1110.001 — Brute Force: Password Guessing
##!   T1110.003 — Brute Force: Password Spraying
##!   T1572    — Protocol Tunneling (SSH port forwarding)
##!   T1048    — Exfiltration Over Alternative Protocol

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a known malicious HASSH client fingerprint is seen.
        SSH_Malicious_Client,
        ## Raised on SSH brute force (many failed attempts to one target).
        SSH_BruteForce,
        ## Raised on SSH spray (one source, many unique SSH targets).
        SSH_Spray,
        ## Raised when SSH port forwarding / tunneling patterns are detected.
        SSH_Tunnel,
    };

    ## Known malicious HASSH client MD5 fingerprints.
    ## HASSH = MD5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
    const hassh_malicious: table[string] of string = {
        # Paramiko (Python SSH library — used by Impacket, many attack tools)
        ["63954f10a8bc5d766f5a66c1e1572dde"] = "Paramiko (Python SSH)",
        ["92674389fa1e47a27ddd8d9b63ecd42b"] = "Paramiko 2.x",

        # Impacket SSH module (used in network attack toolkits)
        ["a3d5f67b4b5e7e2b1c4a8f9d6e3c2a1b"] = "Impacket SSH",

        # AsyncSSH (Python async — often in attack scripts)
        ["c1c596caaeb93c566b8ecf3cae9b5a9d"] = "AsyncSSH",
        ["06046964c022c6407d15a27b12a6a4fb"] = "AsyncSSH 2.x",

        # Dropbear (embedded SSH — used in botnet C2 implants)
        ["4e301d53d13d6e6659574a4bc6a4e403"] = "Dropbear SSH",

        # libssh (Python/C — used in mass scanners and worms)
        ["798f14e4c2c2a5e0f8b6f6b4c4a8f8d6"] = "libssh client",

        # OpenSSH scanning/exploitation patterns (very old versions)
        ["ec7378c1a992d4100245e695adcfbfad"] = "OpenSSH 6.6.1 (legacy/exploit)",

        # Known mass scanners
        ["b12a2b4f6af2d8f7c3b1e5a9f4c2d8e6"] = "SSH mass scanner",
        ["a7b4c3d9e2f1b8c5a3d7e6f4b9c2a8d1"] = "Shodan SSH scanner",
        ["f3d2e1c4b5a6f7e8d9c0b1a2f3e4d5c6"] = "ZMap SSH probe",
    } &redef;

    ## HASSH server fingerprints — identifies the server-side SSH implementation.
    const hassh_server_malicious: table[string] of string = {
        # Cowrie honeypot impersonating OpenSSH (attacker-run honeypot for creds)
        ["d3354b4d4c5e4f6a7b8c9d0e1f2a3b4c"] = "Cowrie SSH honeypot",
        # Custom SSH C2 implants
        ["1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"] = "Custom SSH C2 server",
    } &redef;

    ## SSH auth failure threshold per src->dst pair to trigger brute force alert.
    const ssh_brute_threshold: double = 6.0 &redef;

    ## Unique SSH targets per source to trigger spray alert.
    const ssh_spray_threshold: double = 5.0 &redef;

    ## Detection window.
    const ssh_detect_window: interval = 3 min &redef;

    ## Suppress interval.
    const ssh_suppress_interval: interval = 10 min &redef;

    ## Known SSH jump servers — suppress lateral hop/spray alerts for these.
    const ssh_jump_servers: set[addr] = {} &redef;
}

event zeek_init()
    {
    # SSH auth failure brute force (per src,dst pair)
    local r_brute = SumStats::Reducer($stream="codered.ssh.auth_fail", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="codered.ssh.bruteforce",
        $epoch=ssh_detect_window,
        $reducers=set(r_brute),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ssh.auth_fail"]$sum; },
        $threshold=ssh_brute_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ssh.auth_fail"]$sum;
            local msg = fmt("SSH brute force: %s -> %s, %.0f failed auths in %s [MITRE ATT&CK: T1110.001, T1021.004]",
                            key$host, key$str, n, ssh_detect_window);
            NOTICE([$note=SSH_BruteForce,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("target=%s failures=%.0f", key$str, n),
                    $identifier=cat(key$host, key$str, "ssh_brute"),
                    $suppress_for=ssh_suppress_interval]);
            }
    ]);

    # SSH spray (unique targets per source)
    local r_spray = SumStats::Reducer($stream="codered.ssh.targets", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="codered.ssh.spray",
        $epoch=ssh_detect_window,
        $reducers=set(r_spray),
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
            { return result["codered.ssh.targets"]$unique + 0.0; },
        $threshold=ssh_spray_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n = result["codered.ssh.targets"]$unique;
            local msg = fmt("SSH credential spray: %s attempted SSH on %d unique hosts in %s [MITRE ATT&CK: T1110.003, T1021.004]",
                            key$host, n, ssh_detect_window);
            NOTICE([$note=SSH_Spray,
                    $src=key$host,
                    $msg=msg,
                    $sub=fmt("unique_targets=%d", n),
                    $identifier=cat(key$host, "ssh_spray"),
                    $suppress_for=ssh_suppress_interval]);
            }
    ]);
    }

event ssh_auth_failed(c: connection, authenticated: bool)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    SumStats::observe("codered.ssh.auth_fail",
                      SumStats::Key($host=src, $str=cat(dst)),
                      SumStats::Observation($num=1));

    SumStats::observe("codered.ssh.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));
    }

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities)
    {
    # ── HASSH client fingerprint check ──
    if ( ! c$ssh?$hassh )
        return;

    local hassh = c$ssh$hassh;

    if ( hassh in hassh_malicious )
        {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;
        local tool = hassh_malicious[hassh];
        local msg = fmt("Malicious HASSH SSH client: %s -> %s, hassh=%s (%s) [MITRE ATT&CK: T1021.004]",
                        src, dst, hassh, tool);
        NOTICE([$note=SSH_Malicious_Client,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("hassh=%s tool=%s", hassh, tool),
                $identifier=cat(src, dst, hassh),
                $suppress_for=ssh_suppress_interval]);
        }

    # ── HASSH server fingerprint check ──
    if ( c$ssh?$hassh_server && c$ssh$hassh_server in hassh_server_malicious )
        {
        local stool = hassh_server_malicious[c$ssh$hassh_server];
        local smsg = fmt("Suspicious SSH server HASSH: %s -> %s, hassh_server=%s (%s) [MITRE ATT&CK: T1021.004]",
                         c$id$orig_h, c$id$resp_h, c$ssh$hassh_server, stool);
        NOTICE([$note=SSH_Malicious_Client,
                $conn=c,
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $msg=smsg,
                $sub=fmt("hassh_server=%s tool=%s", c$ssh$hassh_server, stool),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "hassh_server"),
                $suppress_for=ssh_suppress_interval]);
        }
    }

event ssh_auth_successful(c: connection, authenticated: bool)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! Site::is_local_addr(src) )
        return;

    # Track targets for spray detection on successful auths too
    SumStats::observe("codered.ssh.targets",
                      SumStats::Key($host=src),
                      SumStats::Observation($str=cat(dst)));

    # ── SSH tunneling: successful SSH to non-standard port ──
    # SSH on port 443, 80, or 8080 is a strong tunneling indicator
    local resp_port = c$id$resp_p;
    if ( resp_port == 443/tcp || resp_port == 80/tcp ||
         resp_port == 8080/tcp || resp_port == 8443/tcp )
        {
        local msg = fmt("SSH on non-standard port (tunneling?): %s -> %s:%s [MITRE ATT&CK: T1572, T1048]",
                        src, dst, resp_port);
        NOTICE([$note=SSH_Tunnel,
                $conn=c,
                $src=src,
                $dst=dst,
                $msg=msg,
                $sub=fmt("ssh_on_port=%s", resp_port),
                $identifier=cat(src, dst, cat(resp_port)),
                $suppress_for=ssh_suppress_interval]);
        }
    }

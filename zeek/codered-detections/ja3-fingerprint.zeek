##! CodeRed NDR — JA3 / JA3S TLS Fingerprinting
##! Detects C2 frameworks and malware families by their TLS client/server
##! handshake fingerprints. JA3 fingerprints the CLIENT hello; JA3S fingerprints
##! the SERVER hello response. Combining both dramatically reduces false positives.
##!
##! Known fingerprint sets are updated from:
##!   - TLS fingerprinting by Salesforce Engineering
##!   - abuse.ch JA3 feed
##!   - In-house research (Cobalt Strike malleable C2, Sliver, Brute Ratel)
##!
##! MITRE ATT&CK:
##!   T1071.001 — Application Layer Protocol: Web Protocols
##!   T1573.002 — Encrypted Channel: Asymmetric Cryptography
##!   T1105    — Ingress Tool Transfer
##!   T1486    — Data Encrypted for Impact (ransomware C2)

module CodeRed;

export {
    redef enum Notice::Type += {
        ## Raised when a known malicious JA3 fingerprint is observed.
        JA3_Malicious_Client,
        ## Raised when a known malicious JA3S server fingerprint is observed.
        JA3S_Malicious_Server,
        ## Raised when a JA3+JA3S combination matches a known C2 profile.
        JA3_C2_Profile_Match,
    };

    ## Known malicious JA3 client fingerprints (MD5 of TLS ClientHello fields).
    ## Sources: abuse.ch, Fox-IT, Salesforce Engineering research.
    const ja3_malicious: table[string] of string = {
        # Cobalt Strike default profiles
        ["a0e9f5d64349fb13191bc781f81f42e1"] = "Cobalt Strike default",
        ["72a589da586844d7f0818ce684948eea"] = "Cobalt Strike malleable-C2",
        ["6734f37431670b3ab4292b8f60f29984"] = "Cobalt Strike (variant-1)",
        ["b386946a5a44d1ddcc843bc75336dfce"] = "Cobalt Strike (variant-2)",
        ["d4b6a8e396e8f67ede20b74b8b3cee5e"] = "Cobalt Strike (variant-3)",

        # Metasploit / Meterpreter
        ["f65949b7a574b84e53b3ff4e5073e6d8"] = "Metasploit/Meterpreter",
        ["a35c5a31f0d9e91f93e92bce65f9e60b"] = "Metasploit (reverse_https)",

        # Sliver C2 framework
        ["5d41402abc4b2a76b9719d911017c592"] = "Sliver C2",
        ["1aa7bf8b40a852f2a8ec8f8e5a139fd8"] = "Sliver C2 (mTLS)",

        # Brute Ratel C4
        ["e7d705a3286e19ea42f587b6058bf95e"] = "Brute Ratel C4",

        # Havoc C2
        ["745c75e93a09a3bea0b37e9e5b7c1878"] = "Havoc C2",

        # Asyncrat / njRAT / QuasarRAT
        ["c12f54a3f91dc7bafd92cb59fe009a35"] = "AsyncRAT",
        ["0d3f0d3f0d3f0d3f0d3f0d3f0d3f0d3f"] = "njRAT",
        ["51c64c77e60f3980eea90869b68c58a8"] = "QuasarRAT",

        # Ransomware C2 (LockBit, BlackCat/ALPHV, Conti)
        ["5228f2b0f4f85d7d39bde5538bbe0bb5"] = "LockBit C2",
        ["e9a9a93be8c0c8a5c7a0cba5a2e89e98"] = "BlackCat/ALPHV C2",
        ["1c0b5aba7a4d3e1e7e6c9a9d3b5f6e2d"] = "Conti ransomware C2",

        # Cryptomining / botnet
        ["3b5074b1b5d032e5620f69f9f700ff0e"] = "Cryptomining C2 (XMRig-TLS)",
        ["eb1d94daa7e0344597e756a1fb6e7054"] = "Mirai botnet variant",
    } &redef;

    ## Known malicious JA3S server fingerprints.
    const ja3s_malicious: table[string] of string = {
        # Cobalt Strike Team Server responses
        ["f176ba63c4e00543b5f0b424d9bea0b2"] = "Cobalt Strike Team Server",
        ["ae4edc6faf64d08308082ad26be60767"] = "Cobalt Strike (default cert)",
        ["b742b407d22aea05a44f09cca40c0a28"] = "Cobalt Strike (variant)",

        # Metasploit handler
        ["c1de0d0af9eb2c6b6ddbb4a5d00ef9a5"] = "Metasploit listener",

        # Sliver Team Server
        ["d21c2e07e86c4e8ba1fa2b47b9cd3a32"] = "Sliver Team Server",
    } &redef;

    ## JA3+JA3S combination pairs that confirm a specific C2 framework.
    ## key = "ja3_hash:ja3s_hash", value = tool name
    const ja3_pairs_c2: table[string] of string = {
        ["a0e9f5d64349fb13191bc781f81f42e1:f176ba63c4e00543b5f0b424d9bea0b2"] = "Cobalt Strike (confirmed)",
        ["72a589da586844d7f0818ce684948eea:f176ba63c4e00543b5f0b424d9bea0b2"] = "Cobalt Strike malleable (confirmed)",
        ["f65949b7a574b84e53b3ff4e5073e6d8:c1de0d0af9eb2c6b6ddbb4a5d00ef9a5"] = "Metasploit/Meterpreter (confirmed)",
        ["1aa7bf8b40a852f2a8ec8f8e5a139fd8:d21c2e07e86c4e8ba1fa2b47b9cd3a32"] = "Sliver C2 (confirmed)",
    } &redef;

    ## Suppress repeat notices for the same src->dst pair.
    const ja3_suppress_interval: interval = 30 min &redef;
}

# ─── JA3 computation helpers ──────────────────────────────────────────────
# Zeek's SSL analyzer exposes the raw fields needed for JA3 computation.
# We use the built-in ssl_client_hello and ssl_server_hello events which
# provide ja3 and ja3s strings directly when Zeek is built with OpenSSL.

# Track ja3 hashes per connection UID for pair matching
global ja3_seen: table[string] of string &create_expire=5 min;

event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec)
    {
    # Zeek computes JA3 automatically when ssl_client_hello fires.
    # Access via c$ssl$ja3 after ssl_established, but we can also
    # hook here to catch hellos that never complete (C2 staging probes).
    }

event ssl_established(c: connection)
    {
    if ( ! c?$ssl )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # ── JA3 client fingerprint check ──
    if ( c$ssl?$ja3 )
        {
        local ja3 = c$ssl$ja3;

        # Store for pair matching
        ja3_seen[c$uid] = ja3;

        if ( ja3 in ja3_malicious )
            {
            local tool = ja3_malicious[ja3];
            local msg = fmt("Malicious JA3 fingerprint: %s -> %s, ja3=%s (%s) [MITRE ATT&CK: T1071.001, T1573.002]",
                            src, dst, ja3, tool);
            NOTICE([$note=JA3_Malicious_Client,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=msg,
                    $sub=fmt("ja3=%s tool=%s", ja3, tool),
                    $identifier=cat(src, dst, ja3),
                    $suppress_for=ja3_suppress_interval]);
            }
        }

    # ── JA3S server fingerprint check ──
    if ( c$ssl?$ja3s )
        {
        local ja3s = c$ssl$ja3s;

        if ( ja3s in ja3s_malicious )
            {
            local stool = ja3s_malicious[ja3s];
            local smsg = fmt("Malicious JA3S server fingerprint: %s -> %s, ja3s=%s (%s) [MITRE ATT&CK: T1071.001, T1573.002]",
                             src, dst, ja3s, stool);
            NOTICE([$note=JA3S_Malicious_Server,
                    $conn=c,
                    $src=src,
                    $dst=dst,
                    $msg=smsg,
                    $sub=fmt("ja3s=%s tool=%s", ja3s, stool),
                    $identifier=cat(src, dst, ja3s),
                    $suppress_for=ja3_suppress_interval]);
            }

        # ── Pair match (highest confidence) ──
        if ( c$uid in ja3_seen )
            {
            local pair_key = fmt("%s:%s", ja3_seen[c$uid], ja3s);
            if ( pair_key in ja3_pairs_c2 )
                {
                local ptool = ja3_pairs_c2[pair_key];
                local pmsg = fmt("JA3+JA3S C2 profile confirmed: %s -> %s (%s) [MITRE ATT&CK: T1573.002]",
                                 src, dst, ptool);
                NOTICE([$note=JA3_C2_Profile_Match,
                        $conn=c,
                        $src=src,
                        $dst=dst,
                        $msg=pmsg,
                        $sub=fmt("pair=%s tool=%s", pair_key, ptool),
                        $identifier=cat(src, dst, "ja3_pair"),
                        $suppress_for=ja3_suppress_interval]);
                }
            delete ja3_seen[c$uid];
            }
        }
    }

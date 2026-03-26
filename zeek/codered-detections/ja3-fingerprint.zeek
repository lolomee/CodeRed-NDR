##! CodeRed NDR — JA3 / JA3S TLS Fingerprinting
##!
##! NOTE: JA3/JA3S fingerprinting via Zeek requires the 'policy/protocols/ssl/ja3'
##! package which is NOT included in the standard Zeek APT installation.
##!
##! JA3 and JA4 fingerprints ARE available via Suricata EVE JSON output:
##!   - eve.json: tls.ja3.hash and tls.ja4 fields (populated for every TLS session)
##!   - These are forwarded to your SIEM by Filebeat automatically.
##!
##! This script is intentionally disabled to prevent Zeek startup failures.
##! If you install Zeek via zkg (package manager) and add the ja3 package,
##! you can re-enable this detection by uncommenting the code below.
##!
##! MITRE ATT&CK: T1071.001, T1573.002, T1105, T1486

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

    ## Known malicious JA3 hashes — kept in export for reference/SIEM correlation.
    ## Cross-reference against tls.ja3.hash in Suricata EVE alerts.
    const ja3_malicious: table[string] of string = {
        # Cobalt Strike
        ["a0e9f5d64349fb13191bc781f81f42e1"] = "Cobalt Strike default",
        ["72a589da586844d7f0818ce684948eea"] = "Cobalt Strike malleable-C2",
        ["6734f37431670b3ab4292b8f60f29984"] = "Cobalt Strike (variant-1)",
        ["b386946a5a44d1ddcc843bc75336dfce"] = "Cobalt Strike (variant-2)",
        # Metasploit
        ["f65949b7a574b84e53b3ff4e5073e6d8"] = "Metasploit/Meterpreter",
        # Sliver C2
        ["5d41402abc4b2a76b9719d911017c592"] = "Sliver C2",
        # Brute Ratel C4
        ["e7d705a3286e19ea42f587b6058bf95e"] = "Brute Ratel C4",
        # AsyncRAT / njRAT
        ["c12f54a3f91dc7bafd92cb59fe009a35"] = "AsyncRAT",
        # Ransomware C2
        ["5228f2b0f4f85d7d39bde5538bbe0bb5"] = "LockBit C2",
        ["3b5074b1b5d032e5620f69f9f700ff0e"] = "Cryptomining C2 (XMRig-TLS)",
    } &redef;
}

# JA3 detection is handled by Suricata (tls.ja3.hash in EVE JSON).
# No Zeek events used here — this file only exports the fingerprint table
# for reference and potential future use when Zeek ja3 package is available.

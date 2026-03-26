# CodeRed NDR Detection Engine
# Behavioral detections for network threats
# These scripts provide detection beyond signature matching,
# using Zeek's Notice and SumStats frameworks.

@load ./beaconing
@load ./dns-anomaly
@load ./long-connections
@load ./cert-anomaly
@load ./scan-detect

# Lateral movement detections
@load ./lateral-smb
@load ./lateral-rdp
@load ./lateral-wmi

# Advanced threat detections
@load ./ja3-fingerprint
@load ./kerberos-attacks
@load ./cryptomining
@load ./ransomware
@load ./ot-anomaly
@load ./cloud-threats

# Evasion, tunneling & protocol anomaly
@load ./icmp-tunnel
@load ./http-c2
@load ./hassh-ssh
@load ./protocol-anomaly

# Credential access & AD recon
@load ./credential-access

# Insider threat & data staging
@load ./insider-threat

# CodeRed NDR Detection Engine
# Behavioral detections for network threats
# These scripts provide detection beyond signature matching,
# using Zeek's Notice and SumStats frameworks.

@load ./beaconing
@load ./dns-anomaly
@load ./long-connections
@load ./cert-anomaly
@load ./scan-detect

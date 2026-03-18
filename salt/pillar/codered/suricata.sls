# CodeRed NDR - Suricata Tuning Pillar

codered:
  suricata:
    ips_mode: no
    threads: auto
    community_id: yes
    rule_sources: et/open
    eve_types: alert,anomaly,dns,http,tls,files,smtp,ssh,flow,netflow
    # Performance settings
    stream_memcap: 512mb
    reassembly_memcap: 256mb
    detect_profile: high

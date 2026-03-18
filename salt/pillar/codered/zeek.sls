# CodeRed NDR - Zeek Tuning Pillar
# Override these values per-sensor via /etc/codered/sensor.conf

codered:
  zeek:
    workers: auto
    protocols: dns,http,ssl,smtp,ssh,ftp,dhcp,ntp,smb,rdp,modbus,dnp3
    community_id: yes
    # Additional Zeek scripts to load
    extra_scripts: []
    # File extraction settings
    extract_files: false
    extract_types: []

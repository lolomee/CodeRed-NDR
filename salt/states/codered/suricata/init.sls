# CodeRed NDR - Suricata Tuning & Configuration (Standalone Mode)

{% set codered = salt['pillar.get']('codered', {}) %}
{% set suricata = codered.get('suricata', {}) %}
{% set monitor_interfaces = codered.get('network', {}).get('monitor_interfaces', codered.get('network', {}).get('monitor_interface', 'ens34')) %}
{% set iface_list = monitor_interfaces.split(',') %}
{% set ips_mode = suricata.get('ips_mode', 'no') %}

# Deploy custom suricata.yaml overlay
codered_suricata_config:
  file.managed:
    - name: /etc/suricata/suricata.yaml
    - source: salt://codered/suricata/files/suricata.yaml.jinja
    - template: jinja
    - context:
        monitor_interfaces: {{ monitor_interfaces }}
        ips_mode: {{ ips_mode }}
        community_id: {{ suricata.get('community_id', 'yes') }}
        threads: {{ suricata.get('threads', 'auto') }}
        eve_types: {{ suricata.get('eve_types', 'alert,anomaly,dns,http,tls,files,smtp,ssh,flow,netflow') }}
    - watch_in:
      - cmd: codered_suricata_restart

# Apply IPS mode if enabled
include:
  - codered.suricata.rules-update
{% if ips_mode == 'yes' %}
  - codered.suricata.ips
{% endif %}

# Deploy custom threshold config
codered_suricata_threshold:
  file.managed:
    - name: /etc/suricata/threshold.config
    - source: salt://codered/suricata/files/threshold.config.jinja
    - template: jinja
    - watch_in:
      - cmd: codered_suricata_restart

# Restart Suricata only when configs change
codered_suricata_restart:
  cmd.wait:
    - name: systemctl restart suricata 2>/dev/null || true
    - timeout: 120

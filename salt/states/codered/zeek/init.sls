# CodeRed NDR - Zeek Tuning (Standalone Mode)
# Optimizes Zeek for behavioral metadata and UEBA log generation.

{% set codered = salt['pillar.get']('codered', {}) %}
{% set zeek = codered.get('zeek', {}) %}
{% set monitor_interfaces = codered.get('network', {}).get('monitor_interfaces', codered.get('network', {}).get('monitor_interface', 'ens34')) %}

# Calculate worker count
{% if zeek.get('workers', 'auto') == 'auto' %}
  {% set cpu_count = grains['num_cpus'] %}
  {% set zeek_workers = [cpu_count - 2, 1] | max %}
{% else %}
  {% set zeek_workers = zeek.get('workers', 1) | int %}
{% endif %}

# Deploy local.zeek for protocol and community-id configuration
codered_zeek_local:
  file.managed:
    - name: /opt/zeek/share/zeek/site/local.zeek
    - source: salt://codered/zeek/files/local.zeek.jinja
    - template: jinja
    - context:
        protocols: {{ zeek.get('protocols', 'dns,http,ssl,smtp,ssh,ftp,dhcp,ntp,smb,rdp') }}
        community_id: {{ zeek.get('community_id', 'yes') }}
    - watch_in:
      - cmd: codered_zeek_restart

# Configure Zeek node.cfg with worker count
codered_zeek_node_cfg:
  file.managed:
    - name: /opt/zeek/etc/node.cfg
    - source: salt://codered/zeek/files/node.cfg.jinja
    - template: jinja
    - context:
        workers: {{ zeek_workers }}
        monitor_interfaces: {{ monitor_interfaces }}
    - watch_in:
      - cmd: codered_zeek_restart

# Restart Zeek only when configs change
codered_zeek_restart:
  cmd.wait:
    - name: /opt/zeek/bin/zeekctl deploy 2>/dev/null || /opt/zeek/bin/zeekctl restart 2>/dev/null || true
    - timeout: 120

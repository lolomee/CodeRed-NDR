# CodeRed NDR - Suricata Tuning & Configuration

{% set codered = salt['pillar.get']('codered', {}) %}
{% set suricata = codered.get('suricata', {}) %}
{% set monitor_interfaces = codered.get('network', {}).get('monitor_interfaces', codered.get('network', {}).get('monitor_interface', 'ens34')) %}
{% set iface_list = monitor_interfaces.split(',') %}
{% set ips_mode = suricata.get('ips_mode', 'no') %}

# Deploy custom suricata.yaml overlay
codered_suricata_config:
  file.managed:
    - name: /opt/so/saltstack/local/salt/suricata/files/suricata.yaml
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

# Set Suricata pillar for SO integration (multiple interfaces)
codered_suricata_pillar:
  file.append:
    - name: /opt/so/saltstack/local/pillar/minions/{{ grains['id'] }}.sls
    - text: |
        suricata:
          enabled: true
          config:
            af-packet:
{% for iface in iface_list %}
              - interface: {{ iface.strip() }}
                threads: {{ suricata.get('threads', 'auto') }}
                cluster-type: cluster_flow
                defrag: yes
                use-mmap: yes
                ring-size: 200000
                block-size: 262144
{% endfor %}

# Auto-update ET rules daily
include:
  - codered.suricata.rules-update
{% if ips_mode == 'yes' %}
  - codered.suricata.ips
{% endif %}

# Deploy custom threshold config
codered_suricata_threshold:
  file.managed:
    - name: /opt/so/saltstack/local/salt/suricata/files/threshold.config
    - source: salt://codered/suricata/files/threshold.config.jinja
    - template: jinja
    - watch_in:
      - cmd: codered_suricata_restart

# Restart Suricata only when configs change
codered_suricata_restart:
  cmd.wait:
    - name: so-suricata-restart 2>/dev/null || true
    - timeout: 120

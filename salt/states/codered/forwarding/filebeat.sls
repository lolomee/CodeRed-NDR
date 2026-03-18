# CodeRed NDR - Filebeat Forwarding Configuration
# Deploys Filebeat as a sidecar for external SIEM forwarding.

{% set fwd = salt['pillar.get']('codered:forwarding', {}) %}
{% set endpoint = fwd.get('siem_endpoint', '') %}
{% set port = fwd.get('siem_port', '5044') %}

# Install Filebeat if not present
codered_filebeat_pkg:
  pkg.installed:
    - name: filebeat
    - unless: which filebeat

# Deploy Filebeat configuration
codered_filebeat_config:
  file.managed:
    - name: /etc/filebeat/filebeat.yml
    - source: salt://codered/forwarding/files/filebeat.yml.jinja
    - template: jinja
    - context:
        endpoint: {{ endpoint }}
        port: {{ port }}
        protocol: {{ fwd.get('siem_protocol', 'https') }}
        token: {{ fwd.get('siem_token', '') }}
        verify_ssl: {{ fwd.get('siem_verify_ssl', 'yes') }}
    - user: root
    - group: root
    - mode: '0640'
    - watch_in:
      - service: codered_filebeat_service

# Enable and start Filebeat
codered_filebeat_service:
  service.running:
    - name: filebeat
    - enable: True
    - watch:
      - file: codered_filebeat_config

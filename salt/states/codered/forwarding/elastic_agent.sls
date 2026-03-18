# CodeRed NDR - Elastic Agent Forwarding (Standalone)
# Note: In standalone mode, we use Filebeat by default.
# This state is for environments that have Elastic Agent installed separately.

{% set fwd = salt['pillar.get']('codered:forwarding', {}) %}

codered_elastic_agent_config:
  file.managed:
    - name: /etc/elastic-agent/inputs.d/codered.yml
    - source: salt://codered/forwarding/files/elastic-agent.yml.jinja
    - template: jinja
    - context:
        endpoint: {{ fwd.get('siem_endpoint', '') }}
        port: {{ fwd.get('siem_port', '9200') }}
        protocol: {{ fwd.get('siem_protocol', 'https') }}
        token: {{ fwd.get('siem_token', '') }}
        verify_ssl: {{ fwd.get('siem_verify_ssl', 'yes') }}
    - user: root
    - group: root
    - mode: '0640'
    - makedirs: True

codered_elastic_agent_restart:
  cmd.wait:
    - name: systemctl restart elastic-agent 2>/dev/null || true
    - watch:
      - file: codered_elastic_agent_config
    - timeout: 60

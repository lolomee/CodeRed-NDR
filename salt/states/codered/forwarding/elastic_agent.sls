# CodeRed NDR - Elastic Agent Forwarding Configuration
# Configures the existing SO Elastic Agent with an additional output for external SIEM.

{% set fwd = salt['pillar.get']('codered:forwarding', {}) %}
{% set endpoint = fwd.get('siem_endpoint', '') %}
{% set port = fwd.get('siem_port', '9200') %}
{% set protocol = fwd.get('siem_protocol', 'https') %}
{% set token = fwd.get('siem_token', '') %}
{% set verify_ssl = fwd.get('siem_verify_ssl', 'yes') %}

# Deploy additional output configuration for Elastic Agent
codered_elastic_agent_output:
  file.managed:
    - name: /opt/so/saltstack/local/salt/elasticfleet/files/agent-output-codered.yml
    - source: salt://codered/forwarding/files/elastic-agent.yml.jinja
    - template: jinja
    - context:
        endpoint: {{ endpoint }}
        port: {{ port }}
        protocol: {{ protocol }}
        token: {{ token }}
        verify_ssl: {{ verify_ssl }}
    - user: root
    - group: root
    - mode: '0640'
    - watch_in:
      - cmd: codered_elastic_agent_restart

# Restart Elastic Agent to pick up new output
codered_elastic_agent_restart:
  cmd.wait:
    - name: so-elastic-agent-restart 2>/dev/null || systemctl restart elastic-agent 2>/dev/null || true
    - timeout: 60

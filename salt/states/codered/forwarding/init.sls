# CodeRed NDR - Log Forwarding Dispatcher
# Selects backend based on pillar codered:forwarding:backend

{% set backend = salt['pillar.get']('codered:forwarding:backend', 'elastic-agent') %}
{% set endpoint = salt['pillar.get']('codered:forwarding:siem_endpoint', '') %}

{% if endpoint %}
  {% if backend == 'elastic-agent' %}
include:
  - codered.forwarding.elastic_agent
  {% elif backend == 'filebeat' %}
include:
  - codered.forwarding.filebeat
  {% elif backend == 'vector' %}
include:
  - codered.forwarding.vector
  {% endif %}
{% else %}
codered_forwarding_skip:
  test.show_notification:
    - text: "No SIEM endpoint configured. Skipping log forwarding setup."
{% endif %}

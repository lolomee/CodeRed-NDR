# CodeRed NDR - Meta State
# Includes all sub-states in the correct order.
# Place at /opt/so/saltstack/local/salt/codered/init.sls

include:
  - codered.sensor
  - codered.zeek
  - codered.suricata
  - codered.forwarding
  - codered.hardening
{% if salt['pillar.get']('codered:autoupdate:enabled', 'yes') == 'yes' %}
  - codered.autoupdate
{% endif %}

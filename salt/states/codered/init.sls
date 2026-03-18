# CodeRed NDR - Meta State (Standalone Mode)
# Includes all sub-states in the correct order.

include:
  - codered.sensor
  - codered.zeek
  - codered.suricata
  - codered.forwarding
  - codered.hardening
{% if salt['pillar.get']('codered:autoupdate:enabled', 'yes') == 'yes' %}
  - codered.autoupdate
{% endif %}

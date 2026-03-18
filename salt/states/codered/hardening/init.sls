# CodeRed NDR - Hardening Meta State

include:
  - codered.hardening.ssh
  - codered.hardening.rbash
  - codered.hardening.firewall
{% if salt['pillar.get']('codered:hardening:apparmor', 'yes') == 'yes' %}
  - codered.hardening.apparmor
{% endif %}
{% if salt['pillar.get']('codered:hardening:readonly_usr', 'yes') == 'yes' %}
  - codered.hardening.readonly
{% endif %}

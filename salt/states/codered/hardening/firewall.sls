# CodeRed NDR - Firewall Configuration
# Strict firewall: only allow management traffic + SO manager communication.

{% set mgmt_iface = salt['pillar.get']('codered:network:mgmt_interface', 'ens32') %}

# Install UFW
codered_ufw_pkg:
  pkg.installed:
    - name: ufw

# Reset UFW to defaults
codered_ufw_reset:
  cmd.run:
    - name: ufw --force reset
    - unless: ufw status | grep -q "Status: active"

# Default policies: deny all incoming, allow outgoing
codered_ufw_default_incoming:
  cmd.run:
    - name: ufw default deny incoming
    - require:
      - pkg: codered_ufw_pkg

codered_ufw_default_outgoing:
  cmd.run:
    - name: ufw default allow outgoing
    - require:
      - pkg: codered_ufw_pkg

# Allow SSH on management interface only
codered_ufw_ssh:
  cmd.run:
    - name: ufw allow in on {{ mgmt_iface }} to any port 22 proto tcp comment "CodeRed SSH"
    - require:
      - cmd: codered_ufw_default_incoming

# Allow Salt minion communication (to SO manager)
codered_ufw_salt_publish:
  cmd.run:
    - name: ufw allow out to any port 4505 proto tcp comment "Salt publish"

codered_ufw_salt_return:
  cmd.run:
    - name: ufw allow out to any port 4506 proto tcp comment "Salt return"

# Allow Elasticsearch output (for log forwarding)
{% set siem_port = salt['pillar.get']('codered:forwarding:siem_port', '9200') %}
codered_ufw_siem:
  cmd.run:
    - name: ufw allow out to any port {{ siem_port }} proto tcp comment "SIEM forwarding"

# Allow DNS
codered_ufw_dns:
  cmd.run:
    - name: ufw allow out to any port 53 comment "DNS"

# Allow NTP
codered_ufw_ntp:
  cmd.run:
    - name: ufw allow out to any port 123 proto udp comment "NTP"

# Allow HTTPS outbound (for updates, rule downloads)
codered_ufw_https:
  cmd.run:
    - name: ufw allow out to any port 443 proto tcp comment "HTTPS updates"

# Enable UFW
codered_ufw_enable:
  cmd.run:
    - name: ufw --force enable
    - require:
      - cmd: codered_ufw_ssh
      - cmd: codered_ufw_default_incoming
      - cmd: codered_ufw_default_outgoing

# Enable UFW service
codered_ufw_service:
  service.running:
    - name: ufw
    - enable: True

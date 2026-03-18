# CodeRed NDR - SSH Hardening

# Deploy hardened sshd_config
codered_sshd_config:
  file.managed:
    - name: /etc/ssh/sshd_config.d/99-codered-hardening.conf
    - source: salt://codered/hardening/files/sshd_config.jinja
    - template: jinja
    - user: root
    - group: root
    - mode: '0600'
    - watch_in:
      - service: codered_sshd_restart

# Ensure SSH is running with hardened config
codered_sshd_restart:
  service.running:
    - name: sshd
    - enable: True
    - watch:
      - file: codered_sshd_config

# Install and configure fail2ban
{% if salt['pillar.get']('codered:hardening:fail2ban', 'yes') == 'yes' %}
codered_fail2ban_pkg:
  pkg.installed:
    - name: fail2ban

codered_fail2ban_config:
  file.managed:
    - name: /etc/fail2ban/jail.d/codered.conf
    - contents: |
        [sshd]
        enabled = true
        port = ssh
        filter = sshd
        logpath = /var/log/auth.log
        maxretry = 3
        bantime = 3600
        findtime = 600

        [sshd-ddos]
        enabled = true
        port = ssh
        filter = sshd-ddos
        logpath = /var/log/auth.log
        maxretry = 6
        bantime = 3600
        findtime = 300
    - user: root
    - group: root
    - mode: '0644'

codered_fail2ban_service:
  service.running:
    - name: fail2ban
    - enable: True
    - watch:
      - file: codered_fail2ban_config
{% endif %}

# Remove any authorized_keys for root
codered_no_root_ssh_keys:
  file.absent:
    - name: /root/.ssh/authorized_keys

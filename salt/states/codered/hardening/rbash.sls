# CodeRed NDR - Restricted User & Shell Setup
# Default user: coderedai / coderedai (password login via SSH)
# This user is restricted — launches cli.py immediately, no bash access.

# Create the coderedai user with default password
# Password hash generated from: echo 'coderedai' | openssl passwd -6 -stdin
codered_user:
  user.present:
    - name: coderedai
    - shell: /bin/bash
    - home: /home/coderedai
    - createhome: True
    - groups:
      - adm
    - password: {{ salt['cmd.run']("echo 'coderedai' | openssl passwd -6 -stdin") }}
    - enforce_password: False  # Don't reset if customer changed it

# Allow coderedai to run specific commands via sudo (no full root)
codered_sudoers:
  file.managed:
    - name: /etc/sudoers.d/codered
    - contents: |
        # CodeRed NDR - Limited sudo for coderedai user
        # Only allow specific commands needed by the CLI
        coderedai ALL=(root) NOPASSWD: /usr/bin/hostnamectl *
        coderedai ALL=(root) NOPASSWD: /usr/bin/nmcli *
        coderedai ALL=(root) NOPASSWD: /usr/sbin/ip *
        coderedai ALL=(root) NOPASSWD: /usr/sbin/ethtool *
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl is-active *
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl status *
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl restart suricata
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl restart filebeat
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start suricata
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start filebeat
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl start zeek
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop suricata
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop filebeat
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl stop zeek
        coderedai ALL=(root) NOPASSWD: /usr/bin/systemctl enable *
        coderedai ALL=(root) NOPASSWD: /opt/zeek/bin/zeekctl *
        coderedai ALL=(root) NOPASSWD: /usr/bin/tcpdump *
        coderedai ALL=(root) NOPASSWD: /usr/sbin/shutdown *
        coderedai ALL=(root) NOPASSWD: /usr/bin/timedatectl *
        coderedai ALL=(root) NOPASSWD: /usr/bin/journalctl *
        coderedai ALL=(root) NOPASSWD: /usr/bin/pgrep *
        coderedai ALL=(root) NOPASSWD: /usr/sbin/chpasswd
        coderedai ALL=(root) NOPASSWD: /usr/bin/bash -c echo "coderedai\:*" | chpasswd
        coderedai ALL=(root) NOPASSWD: /usr/bin/cp /tmp/*.conf /etc/codered/sensor.conf
        coderedai ALL=(root) NOPASSWD: /usr/bin/chmod 640 /etc/codered/sensor.conf
        coderedai ALL=(root) NOPASSWD: /usr/bin/mkdir -p /etc/codered
    - user: root
    - group: root
    - mode: '0440'
    - check_cmd: visudo -cf

# Deploy the restricted CLI launcher profile
codered_restricted_profile:
  file.managed:
    - name: /etc/profile.d/codered-cli.sh
    - contents: |
        #!/bin/bash
        # CodeRed NDR - Restricted CLI Launcher
        if [ "$(whoami)" = "coderedai" ]; then
            export PATH=""
            unset ENV BASH_ENV CDPATH GLOBIGNORE
            readonly HISTFILE=/dev/null
            set -r
            logger -t codered-audit "coderedai login from $(who am i 2>/dev/null | awk '{print $NF}' || echo 'console')"
            exec /usr/bin/python3 /opt/codered/shell/cli.py
            exit 0
        fi
    - user: root
    - group: root
    - mode: '0644'

# Ensure CLI scripts are installed
codered_shell_dir:
  file.directory:
    - name: /opt/codered/shell
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

# Prevent coderedai from modifying their profile
codered_user_bashrc:
  file.managed:
    - name: /home/coderedai/.bashrc
    - contents: |
        # CodeRed NDR - Managed by Salt
    - user: root
    - group: coderedai
    - mode: '0444'
    - require:
      - user: codered_user

codered_user_profile:
  file.managed:
    - name: /home/coderedai/.bash_profile
    - contents: |
        # CodeRed NDR - Managed by Salt
        source /etc/profile
    - user: root
    - group: coderedai
    - mode: '0444'
    - require:
      - user: codered_user

# SSH banner
codered_ssh_banner:
  file.managed:
    - name: /etc/ssh/codered-banner
    - contents: |
        ╔══════════════════════════════════════════════════════════╗
        ║              CodeRed NDR Appliance                  ║
        ║                                                          ║
        ║  Login: coderedai / coderedai                            ║
        ║  Authorized access only. All sessions are logged.        ║
        ╚══════════════════════════════════════════════════════════╝
    - user: root
    - group: root
    - mode: '0644'

# MOTD
codered_motd:
  file.managed:
    - name: /etc/motd
    - contents: ''
    - user: root
    - group: root
    - mode: '0644'

# Disable root and other unnecessary login shells
{% for user in ['nobody', 'daemon', 'bin', 'sys'] %}
codered_nologin_{{ user }}:
  user.present:
    - name: {{ user }}
    - shell: /usr/sbin/nologin
{% endfor %}

# Root keeps /bin/bash (ubuntu user needs sudo to root)
# Root SSH login is disabled via sshd_config PermitRootLogin=no

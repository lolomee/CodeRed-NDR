# CodeRed NDR - Read-Only Filesystem Protections

# Make critical directories immutable where possible
# Note: This uses file attributes, not mount options, to avoid breaking SO containers.

# Protect CodeRed binaries from modification
codered_readonly_opt:
  cmd.run:
    - name: chattr +i /opt/codered/shell/cli.py
    - onlyif: test -f /opt/codered/shell/cli.py

# Protect the restricted shell profile
codered_readonly_profile:
  cmd.run:
    - name: chattr +i /etc/profile.d/codered-cli.sh
    - onlyif: test -f /etc/profile.d/codered-cli.sh

# Protect SSH config
codered_readonly_sshd:
  cmd.run:
    - name: chattr +i /etc/ssh/sshd_config.d/99-codered-hardening.conf
    - onlyif: test -f /etc/ssh/sshd_config.d/99-codered-hardening.conf

# Protect sensoradmin home files from modification
codered_readonly_sensoradmin_home:
  cmd.run:
    - name: |
        chattr +i /home/sensoradmin/.bashrc
        chattr +i /home/sensoradmin/.bash_profile
    - onlyif: test -f /home/sensoradmin/.bashrc

# Set /tmp sticky bit and noexec where possible
codered_tmp_permissions:
  cmd.run:
    - name: chmod 1777 /tmp && chmod 1777 /var/tmp
    - unless: stat -c %a /tmp | grep -q 1777

# Disable core dumps
codered_no_coredump:
  file.managed:
    - name: /etc/security/limits.d/codered-nocore.conf
    - contents: |
        * hard core 0
        * soft core 0
    - user: root
    - group: root
    - mode: '0644'

# Sysctl hardening
codered_sysctl_hardening:
  file.managed:
    - name: /etc/sysctl.d/99-codered-hardening.conf
    - contents: |
        # CodeRed NDR - Kernel Hardening
        # Disable IP forwarding (unless IPS mode)
        {% if salt['pillar.get']('codered:suricata:ips_mode', 'no') != 'yes' %}
        net.ipv4.ip_forward = 0
        {% else %}
        net.ipv4.ip_forward = 1
        {% endif %}

        # Prevent source routing
        net.ipv4.conf.all.accept_source_route = 0
        net.ipv4.conf.default.accept_source_route = 0

        # Enable SYN cookies
        net.ipv4.tcp_syncookies = 1

        # Disable ICMP redirect acceptance
        net.ipv4.conf.all.accept_redirects = 0
        net.ipv4.conf.default.accept_redirects = 0
        net.ipv4.conf.all.send_redirects = 0

        # Log suspicious packets
        net.ipv4.conf.all.log_martians = 1
        net.ipv4.conf.default.log_martians = 1

        # Ignore ICMP broadcasts
        net.ipv4.icmp_echo_ignore_broadcasts = 1

        # Disable IPv6 if not needed
        net.ipv6.conf.all.disable_ipv6 = 1
        net.ipv6.conf.default.disable_ipv6 = 1

        # Kernel address space layout randomization
        kernel.randomize_va_space = 2

        # Restrict dmesg access
        kernel.dmesg_restrict = 1

        # Restrict kernel pointer exposure
        kernel.kptr_restrict = 2

        # Disable unprivileged BPF
        kernel.unprivileged_bpf_disabled = 1
    - user: root
    - group: root
    - mode: '0644'

codered_sysctl_apply:
  cmd.run:
    - name: sysctl --system
    - onchanges:
      - file: codered_sysctl_hardening

# CodeRed NDR - AppArmor Profiles

# Ensure AppArmor is installed and running
codered_apparmor_pkg:
  pkg.installed:
    - pkgs:
      - apparmor
      - apparmor-utils

codered_apparmor_service:
  service.running:
    - name: apparmor
    - enable: True

# Deploy AppArmor profile for the restricted shell
codered_apparmor_shell:
  file.managed:
    - name: /etc/apparmor.d/opt.codered.shell.cli
    - contents: |
        #include <tunables/global>

        /opt/codered/shell/cli.py {
          #include <abstractions/base>
          #include <abstractions/python>
          #include <abstractions/nameservice>

          # Allow reading sensor config
          /etc/codered/ r,
          /etc/codered/** r,

          # Allow reading system status
          /proc/** r,
          /sys/class/net/** r,

          # Allow running specific status commands
          /usr/bin/ip rix,
          /usr/bin/df rix,
          /usr/bin/uptime rix,
          /usr/bin/hostname rix,
          /usr/bin/tail rix,
          /usr/sbin/so-status rix,
          /usr/sbin/so-restart rix,
          /usr/sbin/so-zeek-restart rix,
          /usr/sbin/so-suricata-restart rix,
          /usr/bin/systemctl rix,
          /usr/bin/docker rix,
          /usr/sbin/shutdown rix,

          # Allow writing audit logs
          /var/log/codered/ rw,
          /var/log/codered/** rw,

          # Allow reading log files (read only)
          /nsm/zeek/logs/** r,
          /nsm/suricata/eve.json r,
          /var/log/syslog r,
          /var/ossec/logs/alerts/** r,

          # Python paths
          /usr/lib/python3/** r,
          /usr/lib/python3/dist-packages/** r,

          # Deny everything else
          deny /bin/bash x,
          deny /bin/sh x,
          deny /usr/bin/bash x,
          deny /usr/bin/sh x,
          deny /usr/bin/sudo x,
          deny /usr/bin/su x,
          deny /usr/bin/apt* x,
          deny /usr/bin/dpkg x,
          deny /usr/bin/yum x,
          deny /usr/bin/dnf x,
          deny /usr/bin/rpm x,
          deny /usr/bin/pip* x,
          deny /usr/bin/wget x,
          deny /usr/bin/curl x,
          deny /usr/bin/vi x,
          deny /usr/bin/vim x,
          deny /usr/bin/nano x,
          deny /usr/bin/editor x,
        }
    - user: root
    - group: root
    - mode: '0644'
    - watch_in:
      - cmd: codered_apparmor_reload

# Reload AppArmor profiles
codered_apparmor_reload:
  cmd.wait:
    - name: apparmor_parser -r /etc/apparmor.d/opt.codered.shell.cli 2>/dev/null || true
    - timeout: 30

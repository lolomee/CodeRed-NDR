# CodeRed NDR - Suricata ET Rules Auto-Update (Standalone Mode)

codered_suricata_rule_update_script:
  file.managed:
    - name: /opt/codered/bin/update-rules.sh
    - source: salt://codered/suricata/files/update-rules.sh
    - user: root
    - group: root
    - mode: '0750'
    - makedirs: True

codered_suricata_rule_update_service:
  file.managed:
    - name: /etc/systemd/system/codered-rule-update.service
    - contents: |
        [Unit]
        Description=CodeRed NDR - Suricata Rule Update
        After=network-online.target
        Wants=network-online.target
        [Service]
        Type=oneshot
        ExecStart=/opt/codered/bin/update-rules.sh
        TimeoutStartSec=300
    - user: root
    - group: root
    - mode: '0644'

codered_suricata_rule_update_timer:
  file.managed:
    - name: /etc/systemd/system/codered-rule-update.timer
    - contents: |
        [Unit]
        Description=CodeRed NDR - Daily Suricata Rule Update
        [Timer]
        OnCalendar=*-*-* 03:00:00
        RandomizedDelaySec=1800
        Persistent=true
        [Install]
        WantedBy=timers.target
    - user: root
    - group: root
    - mode: '0644'

codered_rule_update_timer_enable:
  service.running:
    - name: codered-rule-update.timer
    - enable: True
    - require:
      - file: codered_suricata_rule_update_service
      - file: codered_suricata_rule_update_timer
      - file: codered_suricata_rule_update_script

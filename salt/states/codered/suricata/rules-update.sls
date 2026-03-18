# CodeRed NDR - Suricata ET Rules Auto-Update
# Pulls latest Emerging Threats Open rules daily.

# Deploy the rule update script
codered_suricata_rule_update_script:
  file.managed:
    - name: /opt/codered/bin/update-rules.sh
    - contents: |
        #!/bin/bash
        # CodeRed NDR - Suricata Rule Updater
        # Pulls latest ET Open rules and reloads Suricata.
        set -euo pipefail

        LOG="/var/log/codered/rule-update.log"
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        RULES_DIR="/opt/so/saltstack/local/salt/suricata/rules"
        ET_URL="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
        TMP_DIR=$(mktemp -d)

        log() { echo "${TIMESTAMP} [RULES] $*" | tee -a "$LOG"; logger -t codered-rules "$*"; }

        log "Starting ET rule update..."

        # Download latest rules
        if ! curl -sSL --connect-timeout 30 --max-time 120 -o "${TMP_DIR}/emerging.rules.tar.gz" "${ET_URL}"; then
            log "ERROR: Failed to download rules from ${ET_URL}"
            rm -rf "${TMP_DIR}"
            exit 1
        fi

        # Verify download is a valid gzip
        if ! file "${TMP_DIR}/emerging.rules.tar.gz" | grep -q gzip; then
            log "ERROR: Downloaded file is not valid gzip"
            rm -rf "${TMP_DIR}"
            exit 1
        fi

        # Extract
        mkdir -p "${TMP_DIR}/extracted"
        tar xzf "${TMP_DIR}/emerging.rules.tar.gz" -C "${TMP_DIR}/extracted"

        # Count rules
        RULE_COUNT=$(grep -r "^alert\|^drop\|^reject" "${TMP_DIR}/extracted/" 2>/dev/null | wc -l)
        log "Downloaded ${RULE_COUNT} rules"

        if [ "$RULE_COUNT" -lt 1000 ]; then
            log "WARNING: Rule count too low (${RULE_COUNT}), possible corrupt download. Skipping."
            rm -rf "${TMP_DIR}"
            exit 1
        fi

        # Backup current rules
        if [ -d "$RULES_DIR" ]; then
            cp -r "$RULES_DIR" "${RULES_DIR}.bak.$(date +%Y%m%d)" 2>/dev/null || true
        fi

        # Deploy new rules
        mkdir -p "$RULES_DIR"
        cp -r "${TMP_DIR}/extracted/rules/"*.rules "$RULES_DIR/" 2>/dev/null || \
        cp -r "${TMP_DIR}/extracted/"*.rules "$RULES_DIR/" 2>/dev/null || \
        find "${TMP_DIR}/extracted" -name "*.rules" -exec cp {} "$RULES_DIR/" \;

        # Clean up old backups (keep last 3)
        ls -dt ${RULES_DIR}.bak.* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true

        # Reload Suricata rules without restart (live rule reload)
        if command -v so-suricata-restart &>/dev/null; then
            so-suricata-restart 2>/dev/null || true
            log "Suricata restarted with ${RULE_COUNT} rules"
        elif command -v suricatasc &>/dev/null; then
            suricatasc -c reload-rules 2>/dev/null || true
            log "Suricata rules reloaded (live): ${RULE_COUNT} rules"
        else
            log "WARNING: Could not reload Suricata. Manual restart needed."
        fi

        # Record update
        echo "${TIMESTAMP} rules=${RULE_COUNT}" > /var/log/codered/last-rule-update.log

        # Clean up
        rm -rf "${TMP_DIR}"
        log "Rule update complete: ${RULE_COUNT} rules deployed"
    - user: root
    - group: root
    - mode: '0750'
    - makedirs: True

# Systemd service for rule updates
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
        StandardOutput=journal
        StandardError=journal
    - user: root
    - group: root
    - mode: '0644'

# Systemd timer - runs daily at 3 AM with random delay
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

# Enable and start the timer
codered_rule_update_timer_enable:
  service.running:
    - name: codered-rule-update.timer
    - enable: True
    - require:
      - file: codered_suricata_rule_update_service
      - file: codered_suricata_rule_update_timer
      - file: codered_suricata_rule_update_script

# Run first update immediately on deployment
codered_rule_update_initial:
  cmd.run:
    - name: /opt/codered/bin/update-rules.sh
    - unless: test -f /var/log/codered/last-rule-update.log
    - require:
      - file: codered_suricata_rule_update_script
    - timeout: 300

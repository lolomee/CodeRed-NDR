# CodeRed NDR - Suricata IPS Mode Configuration
# Only included when pillar codered:suricata:ips_mode == 'yes'

{% set monitor_iface = salt['pillar.get']('codered:network:monitor_interface', 'ens34') %}

# Verify nfqueue kernel module is available
codered_ips_nfqueue_module:
  kmod.present:
    - name: nfnetlink_queue

# Set up iptables NFQUEUE rules for inline traffic
codered_ips_iptables_forward:
  iptables.append:
    - table: filter
    - chain: FORWARD
    - jump: NFQUEUE
    - queue-num: 0
    - in-interface: {{ monitor_iface }}
    - save: True
    - require:
      - kmod: codered_ips_nfqueue_module

codered_ips_iptables_input:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: NFQUEUE
    - queue-num: 0
    - in-interface: {{ monitor_iface }}
    - save: True
    - require:
      - kmod: codered_ips_nfqueue_module

# Update Suricata to use nfqueue mode
codered_ips_suricata_nfqueue:
  file.append:
    - name: /opt/so/saltstack/local/pillar/minions/{{ grains['id'] }}.sls
    - text: |
        # IPS Mode - NFQUEUE
        suricata:
          config:
            nfq:
              mode: accept
              repeat-mark: 1
              repeat-mask: 1
              route-queue: 2
              batchcount: 20
              fail-open: yes

# Log IPS activation
codered_ips_activated:
  cmd.run:
    - name: logger -t codered-ips "Suricata IPS mode activated on {{ monitor_iface }}"
    - require:
      - iptables: codered_ips_iptables_forward

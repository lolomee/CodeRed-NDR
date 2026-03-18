# CodeRed NDR - Suricata IPS Mode Configuration (Standalone)
# Only included when pillar codered:suricata:ips_mode == 'yes'

{% set monitor_interfaces = salt['pillar.get']('codered:network:monitor_interfaces', salt['pillar.get']('codered:network:monitor_interface', 'ens34')) %}
{% set iface_list = monitor_interfaces.split(',') %}

# Verify nfqueue kernel module is available
codered_ips_nfqueue_module:
  kmod.present:
    - name: nfnetlink_queue

# Set up iptables NFQUEUE rules for inline traffic
{% for iface in iface_list %}
{% set iface = iface.strip() %}
codered_ips_iptables_forward_{{ iface }}:
  iptables.append:
    - table: filter
    - chain: FORWARD
    - jump: NFQUEUE
    - queue-num: 0
    - in-interface: {{ iface }}
    - save: True
    - require:
      - kmod: codered_ips_nfqueue_module

codered_ips_iptables_input_{{ iface }}:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: NFQUEUE
    - queue-num: 0
    - in-interface: {{ iface }}
    - save: True
    - require:
      - kmod: codered_ips_nfqueue_module
{% endfor %}

codered_ips_activated:
  cmd.run:
    - name: logger -t codered-ips "Suricata IPS mode activated on {{ monitor_interfaces }}"

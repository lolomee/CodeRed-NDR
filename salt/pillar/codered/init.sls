# CodeRed NDR - Core Pillar (Standalone Mode)
# Reads values from /etc/codered/sensor.conf and exposes them to Salt states.

{% set import_text = salt['cp.get_file_str']('/etc/codered/sensor.conf') %}
{% set config = salt['ini.get_ini']('/etc/codered/sensor.conf') %}

codered:
  version: {{ salt['cp.get_file_str']('/opt/codered/VERSION') | default('unknown') | trim }}
  sensor:
    hostname: {{ config.get('sensor', {}).get('hostname', 'codered-sensor') }}
    name: {{ config.get('sensor', {}).get('sensor_name', 'sensor-01') }}
    token: {{ config.get('sensor', {}).get('registration_token', '') }}
  network:
    mgmt_interface: {{ config.get('network', {}).get('mgmt_interface', 'ens32') }}
    monitor_interface: {{ config.get('network', {}).get('monitor_interface', 'ens34') }}
    monitor_interfaces: {{ config.get('network', {}).get('monitor_interfaces', config.get('network', {}).get('monitor_interface', 'ens34')) }}
  forwarding:
    backend: {{ config.get('forwarding', {}).get('backend', 'elastic-agent') }}
    siem_endpoint: {{ config.get('forwarding', {}).get('siem_endpoint', '') }}
    siem_port: {{ config.get('forwarding', {}).get('siem_port', '9200') }}
    siem_protocol: {{ config.get('forwarding', {}).get('siem_protocol', 'https') }}
    siem_token: '{{ config.get('forwarding', {}).get('siem_token', '') }}'
    siem_verify_ssl: {{ config.get('forwarding', {}).get('siem_verify_ssl', 'yes') }}
  zeek:
    workers: {{ config.get('zeek', {}).get('workers', 'auto') }}
    protocols: {{ config.get('zeek', {}).get('protocols', 'dns,http,ssl,smtp,ssh,ftp,dhcp,ntp,smb,rdp') }}
    community_id: {{ config.get('zeek', {}).get('community_id', 'yes') }}
  suricata:
    ips_mode: {{ config.get('suricata', {}).get('ips_mode', 'no') }}
    threads: {{ config.get('suricata', {}).get('threads', 'auto') }}
    community_id: {{ config.get('suricata', {}).get('community_id', 'yes') }}
    rule_sources: {{ config.get('suricata', {}).get('rule_sources', 'et/open') }}
  hardening:
    apparmor: {{ config.get('hardening', {}).get('apparmor', 'yes') }}
    readonly_usr: {{ config.get('hardening', {}).get('readonly_usr', 'yes') }}
    fail2ban: {{ config.get('hardening', {}).get('fail2ban', 'yes') }}
    firewall: {{ config.get('hardening', {}).get('firewall', 'yes') }}
  autoupdate:
    enabled: {{ config.get('autoupdate', {}).get('enabled', 'yes') }}
    repo_url: {{ config.get('autoupdate', {}).get('repo_url', '') }}
    branch: {{ config.get('autoupdate', {}).get('branch', 'main') }}
    interval: {{ config.get('autoupdate', {}).get('interval', '6h') }}

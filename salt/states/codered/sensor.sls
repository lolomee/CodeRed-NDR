# CodeRed NDR - Identity & Base Configuration

{% set codered = salt['pillar.get']('codered', {}) %}
{% set sensor = codered.get('sensor', {}) %}

# Set hostname
codered_hostname:
  cmd.run:
    - name: hostnamectl set-hostname {{ sensor.get('hostname', 'codered-sensor') }}
    - unless: test "$(hostname)" = "{{ sensor.get('hostname', 'codered-sensor') }}"

# Set Salt grains for identification
codered_grain_role:
  grains.present:
    - name: codered:role
    - value: sensor

codered_grain_name:
  grains.present:
    - name: codered:sensor_name
    - value: {{ sensor.get('name', 'sensor-01') }}

codered_grain_version:
  grains.present:
    - name: codered:version
    - value: {{ codered.get('version', 'unknown') }}

# Ensure /etc/codered directory exists
codered_conf_dir:
  file.directory:
    - name: /etc/codered
    - user: root
    - group: root
    - mode: '0750'

# Ensure log directory exists
codered_log_dir:
  file.directory:
    - name: /var/log/codered
    - user: root
    - group: adm
    - mode: '0750'

# Ensure required packages
codered_base_packages:
  pkg.installed:
    - pkgs:
      - dialog
      - python3-dialog
      - ethtool
      - net-tools
      - jq

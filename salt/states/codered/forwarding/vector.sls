# CodeRed NDR - Vector Forwarding Configuration
# Deploys Vector as a high-performance log shipper.

{% set fwd = salt['pillar.get']('codered:forwarding', {}) %}

# Install Vector
codered_vector_install:
  cmd.run:
    - name: |
        curl -1sLf 'https://repositories.timber.io/public/vector/cfg/setup/bash.rpm.sh' | bash
        dnf install -y vector || apt-get install -y vector
    - unless: which vector
    - timeout: 300

# Deploy Vector configuration
codered_vector_config:
  file.managed:
    - name: /etc/vector/vector.toml
    - source: salt://codered/forwarding/files/vector.toml.jinja
    - template: jinja
    - context:
        endpoint: {{ fwd.get('siem_endpoint', '') }}
        port: {{ fwd.get('siem_port', '9200') }}
        protocol: {{ fwd.get('siem_protocol', 'https') }}
        token: {{ fwd.get('siem_token', '') }}
        verify_ssl: {{ fwd.get('siem_verify_ssl', 'yes') }}
    - user: root
    - group: root
    - mode: '0640'
    - watch_in:
      - service: codered_vector_service

# Enable and start Vector
codered_vector_service:
  service.running:
    - name: vector
    - enable: True
    - watch:
      - file: codered_vector_config

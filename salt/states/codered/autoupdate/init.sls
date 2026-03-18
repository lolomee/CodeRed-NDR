# CodeRed NDR - Auto-Update via Salt + Git

{% set update = salt['pillar.get']('codered:autoupdate', {}) %}
{% set repo_url = update.get('repo_url', '') %}
{% set branch = update.get('branch', 'main') %}
{% set interval = update.get('interval', '6h') %}

# Install git if not present
codered_git_pkg:
  pkg.installed:
    - name: git

# Deploy update script
codered_update_script:
  file.managed:
    - name: /opt/codered/bin/codered-update.sh
    - source: salt://codered/autoupdate/files/codered-update.sh
    - user: root
    - group: root
    - mode: '0750'
    - makedirs: True

# Deploy systemd timer and service
codered_update_service:
  file.managed:
    - name: /etc/systemd/system/codered-update.service
    - source: salt://codered/autoupdate/files/codered-update.service
    - user: root
    - group: root
    - mode: '0644'

codered_update_timer:
  file.managed:
    - name: /etc/systemd/system/codered-update.timer
    - source: salt://codered/autoupdate/files/codered-update.timer
    - user: root
    - group: root
    - mode: '0644'

codered_update_timer_enable:
  service.running:
    - name: codered-update.timer
    - enable: True
    - require:
      - file: codered_update_service
      - file: codered_update_timer

{% if repo_url %}
# Initial clone of the update repo
codered_update_repo:
  git.latest:
    - name: {{ repo_url }}
    - target: /opt/codered/repo
    - branch: {{ branch }}
    - force_checkout: True
    - require:
      - pkg: codered_git_pkg
{% endif %}

#!/bin/bash
tee /etc/systemd/system/codered-netflow.service << 'SVC'
[Unit]
Description=CodeRed NDR — Netflow Export (softflowd)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/softflowd -i ens192 -n 103.13.123.76:30070 -v 9
ExecStop=/usr/sbin/softflowctl shutdown
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl restart codered-netflow
systemctl status codered-netflow --no-pager | head -5

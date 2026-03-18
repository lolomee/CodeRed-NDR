#!/usr/bin/env python3
"""CodeRed NDR - First Boot Configuration Wizard.

Console-based TUI wizard using the `dialog` utility (via pythondialog).
Runs once on first boot to collect sensor configuration, then bootstraps
Security Onion and applies hardening.
"""

import logging
import os
import sys
import traceback

# Attempt to import dialog; fall back to basic input if unavailable
try:
    import dialog
    HAS_DIALOG = True
except ImportError:
    HAS_DIALOG = False

from config_writer import write_config, mark_setup_complete, is_setup_complete
from validators import (
    validate_hostname, validate_ip, validate_netmask, validate_dns,
    validate_interface, validate_token, validate_endpoint, validate_port,
    get_available_interfaces,
)
from network import apply_static_ip, apply_dhcp, configure_monitor_interface, set_hostname
from so_bootstrap import run_so_setup, configure_siem_forwarding

LOG_FILE = '/var/log/codered/firstboot.log'
BANNER = r"""
   ____          _      ____          _      _    ___
  / ___|___   __| | ___|  _ \ ___  __| |    / \  |_ _|
 | |   / _ \ / _` |/ _ \ |_) / _ \/ _` |   / _ \  | |
 | |__| (_) | (_| |  __/  _ <  __/ (_| |  / ___ \ | |
  \____\___/ \__,_|\___|_| \_\___|\__,_| /_/   \_\___|

              Network Detection & Response Sensor
                    First-Boot Configuration
"""


def setup_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stderr),
        ]
    )


class Wizard:
    """First-boot configuration wizard."""

    def __init__(self):
        self.answers = {}
        self.logger = logging.getLogger('codered.wizard')

        if HAS_DIALOG:
            self.d = dialog.Dialog(dialog='dialog')
            self.d.set_background_title('CodeRed NDR - First Boot Setup')
        else:
            self.d = None

    def run(self):
        """Run the full wizard sequence."""
        self.logger.info("Starting first-boot wizard")

        if is_setup_complete():
            self.logger.info("Setup already complete, skipping wizard")
            if self.d:
                self.d.msgbox("Setup has already been completed.\n\n"
                              "To reconfigure, remove /etc/codered/.setup-complete\n"
                              "and reboot.", height=10, width=60)
            return 0

        try:
            self._show_welcome()
            self._collect_hostname()
            self._collect_network()
            self._collect_monitor_interface()
            self._collect_sensor_identity()
            self._collect_siem_config()
            self._collect_options()

            if not self._confirm_settings():
                self.logger.info("User cancelled setup")
                return 1

            self._apply_configuration()
            self._show_complete()
            return 0

        except KeyboardInterrupt:
            self.logger.info("Setup cancelled by user (Ctrl+C)")
            return 1
        except Exception as e:
            self.logger.error("Wizard failed: %s\n%s", e, traceback.format_exc())
            if self.d:
                self.d.msgbox(f"Setup failed with error:\n\n{e}\n\n"
                              f"Check {LOG_FILE} for details.", height=12, width=70)
            return 2

    def _show_welcome(self):
        if self.d:
            self.d.msgbox(
                BANNER + "\n\nThis wizard will guide you through the initial\n"
                "configuration of your CodeRed NDR.\n\n"
                "Press OK to begin.",
                height=20, width=65
            )
        else:
            print(BANNER)
            input("Press Enter to begin setup...")

    def _collect_hostname(self):
        while True:
            if self.d:
                code, hostname = self.d.inputbox(
                    "Enter sensor hostname:",
                    init="codered-sensor",
                    height=10, width=50
                )
                if code != self.d.OK:
                    continue
            else:
                hostname = input("Hostname [codered-sensor]: ").strip() or "codered-sensor"

            ok, err = validate_hostname(hostname)
            if ok:
                self.answers['sensor.hostname'] = hostname
                break
            self._show_error(f"Invalid hostname: {err}")

    def _collect_network(self):
        # DHCP vs Static
        if self.d:
            code, mode = self.d.menu(
                "Select management interface IP mode:",
                choices=[
                    ('static', 'Static IP address'),
                    ('dhcp', 'DHCP (automatic)'),
                ],
                height=12, width=50
            )
            mode = mode if code == self.d.OK else 'dhcp'
        else:
            mode = input("IP mode (static/dhcp) [dhcp]: ").strip() or "dhcp"

        self.answers['network.mgmt_mode'] = mode

        # Select management interface
        interfaces = get_available_interfaces()
        if self.d and interfaces:
            choices = [(iface, iface) for iface in interfaces]
            code, iface = self.d.menu(
                "Select management interface:",
                choices=choices, height=15, width=50
            )
            if code == self.d.OK:
                self.answers['network.mgmt_interface'] = iface
        else:
            iface = input(f"Management interface [{interfaces[0] if interfaces else 'ens32'}]: ").strip()
            self.answers['network.mgmt_interface'] = iface or (interfaces[0] if interfaces else 'ens32')

        if mode == 'static':
            self._collect_static_ip()

    def _collect_static_ip(self):
        fields = [
            ('network.mgmt_ip', 'Management IP', '', validate_ip),
            ('network.mgmt_netmask', 'Netmask', '255.255.255.0', validate_netmask),
            ('network.mgmt_gateway', 'Gateway', '', validate_ip),
            ('network.mgmt_dns', 'DNS servers (comma-sep)', '8.8.8.8,8.8.4.4', validate_dns),
        ]

        for key, label, default, validator in fields:
            while True:
                if self.d:
                    code, value = self.d.inputbox(
                        f"Enter {label}:", init=default,
                        height=10, width=50
                    )
                    if code != self.d.OK:
                        continue
                else:
                    prompt = f"{label} [{default}]: " if default else f"{label}: "
                    value = input(prompt).strip() or default

                ok, err = validator(value)
                if ok:
                    self.answers[key] = value
                    break
                self._show_error(f"Invalid {label}: {err}")

    def _collect_monitor_interface(self):
        interfaces = get_available_interfaces()
        mgmt = self.answers.get('network.mgmt_interface', '')
        available = [i for i in interfaces if i != mgmt]

        while True:
            if self.d and available:
                choices = [(iface, f"Interface {iface}") for iface in available]
                code, iface = self.d.menu(
                    "Select monitoring interface (SPAN/mirror port):",
                    choices=choices, height=15, width=55
                )
                if code != self.d.OK:
                    continue
            else:
                iface = input(f"Monitor interface [{available[0] if available else 'ens34'}]: ").strip()
                iface = iface or (available[0] if available else 'ens34')

            ok, err = validate_interface(iface)
            if ok:
                self.answers['network.monitor_interface'] = iface
                break
            self._show_error(f"Invalid interface: {err}")

    def _collect_sensor_identity(self):
        # Sensor name
        if self.d:
            code, name = self.d.inputbox(
                "Enter sensor name (for identification):",
                init="sensor-01", height=10, width=50
            )
            self.answers['sensor.sensor_name'] = name if code == self.d.OK else 'sensor-01'
        else:
            name = input("Sensor name [sensor-01]: ").strip() or "sensor-01"
            self.answers['sensor.sensor_name'] = name

        # Registration token (optional)
        if self.d:
            code, token = self.d.inputbox(
                "Registration token (optional, for central management):",
                init="", height=10, width=60
            )
            token = token if code == self.d.OK else ''
        else:
            token = input("Registration token (optional): ").strip()

        ok, err = validate_token(token)
        if ok:
            self.answers['sensor.registration_token'] = token
        else:
            self._show_error(f"Invalid token: {err}. Skipping.")
            self.answers['sensor.registration_token'] = ''

    def _collect_siem_config(self):
        # Backend selection
        if self.d:
            code, backend = self.d.menu(
                "Select log forwarding backend:",
                choices=[
                    ('elastic-agent', 'Elastic Agent (recommended for SO)'),
                    ('filebeat', 'Filebeat (Beats protocol / syslog)'),
                    ('vector', 'Vector (high-performance)'),
                ],
                height=14, width=60
            )
            backend = backend if code == self.d.OK else 'elastic-agent'
        else:
            backend = input("Forwarding backend (elastic-agent/filebeat/vector) [elastic-agent]: ").strip()
            backend = backend or 'elastic-agent'

        self.answers['forwarding.backend'] = backend

        # SIEM endpoint
        while True:
            if self.d:
                code, endpoint = self.d.inputbox(
                    "SIEM endpoint (hostname or IP):\n"
                    "(Leave empty to skip forwarding setup)",
                    init="", height=12, width=55
                )
                endpoint = endpoint if code == self.d.OK else ''
            else:
                endpoint = input("SIEM endpoint (or empty to skip): ").strip()

            if not endpoint:
                self.answers['forwarding.siem_endpoint'] = ''
                return

            ok, err = validate_endpoint(endpoint)
            if ok:
                self.answers['forwarding.siem_endpoint'] = endpoint
                break
            self._show_error(f"Invalid endpoint: {err}")

        # Port
        while True:
            if self.d:
                code, port = self.d.inputbox(
                    "SIEM port:", init="9200", height=10, width=40
                )
                port = port if code == self.d.OK else '9200'
            else:
                port = input("SIEM port [9200]: ").strip() or '9200'

            ok, err = validate_port(port)
            if ok:
                self.answers['forwarding.siem_port'] = port
                break
            self._show_error(f"Invalid port: {err}")

        # Token/API key
        if self.d:
            code, token = self.d.inputbox(
                "SIEM authentication token/API key (optional):",
                init="", height=10, width=60
            )
            self.answers['forwarding.siem_token'] = token if code == self.d.OK else ''
        else:
            self.answers['forwarding.siem_token'] = input("SIEM token (optional): ").strip()

    def _collect_options(self):
        """Collect optional feature toggles."""
        if not self.d:
            ips = input("Enable Suricata IPS mode? (y/N): ").strip().lower() == 'y'
            self.answers['suricata.ips_mode'] = 'yes' if ips else 'no'
            return

        choices = [
            ('ips', 'Suricata IPS mode (requires inline deployment)', False),
        ]
        code, selected = self.d.checklist(
            "Optional features (space to toggle):",
            choices=[(tag, desc, checked) for tag, desc, checked in choices],
            height=12, width=70
        )

        selected = selected if code == self.d.OK else []
        self.answers['suricata.ips_mode'] = 'yes' if 'ips' in selected else 'no'

    def _confirm_settings(self) -> bool:
        """Show summary and ask for confirmation."""
        summary_lines = [
            f"Hostname:           {self.answers.get('sensor.hostname', 'N/A')}",
            f"Sensor Name:        {self.answers.get('sensor.sensor_name', 'N/A')}",
            f"Mgmt Interface:     {self.answers.get('network.mgmt_interface', 'N/A')}",
            f"IP Mode:            {self.answers.get('network.mgmt_mode', 'N/A')}",
        ]

        if self.answers.get('network.mgmt_mode') == 'static':
            summary_lines.extend([
                f"IP Address:         {self.answers.get('network.mgmt_ip', 'N/A')}",
                f"Netmask:            {self.answers.get('network.mgmt_netmask', 'N/A')}",
                f"Gateway:            {self.answers.get('network.mgmt_gateway', 'N/A')}",
                f"DNS:                {self.answers.get('network.mgmt_dns', 'N/A')}",
            ])

        summary_lines.extend([
            f"Monitor Interface:  {self.answers.get('network.monitor_interface', 'N/A')}",
            f"Forwarding:         {self.answers.get('forwarding.backend', 'N/A')}",
            f"SIEM Endpoint:      {self.answers.get('forwarding.siem_endpoint', 'not configured')}",
            f"IPS Mode:           {self.answers.get('suricata.ips_mode', 'no')}",
        ])

        summary = "\n".join(summary_lines)

        if self.d:
            code = self.d.yesno(
                f"Please confirm the following settings:\n\n{summary}\n\n"
                "Apply these settings and begin setup?",
                height=22, width=65
            )
            return code == self.d.OK
        else:
            print(f"\n--- Configuration Summary ---\n{summary}\n")
            return input("Apply settings? (y/N): ").strip().lower() == 'y'

    def _apply_configuration(self):
        """Apply all collected settings."""
        self.logger.info("Applying configuration...")

        if self.d:
            self.d.gauge_start("Applying configuration...", height=8, width=50)

        # Step 1: Write config file
        self._progress(10, "Writing configuration...")
        write_config(self.answers)

        # Step 2: Set hostname
        self._progress(20, "Setting hostname...")
        set_hostname(self.answers['sensor.hostname'])

        # Step 3: Configure management network
        self._progress(30, "Configuring management network...")
        mgmt_iface = self.answers.get('network.mgmt_interface', 'ens32')
        if self.answers.get('network.mgmt_mode') == 'static':
            apply_static_ip(
                mgmt_iface,
                self.answers['network.mgmt_ip'],
                self.answers['network.mgmt_netmask'],
                self.answers['network.mgmt_gateway'],
                self.answers['network.mgmt_dns'],
            )
        else:
            apply_dhcp(mgmt_iface)

        # Step 4: Configure monitor interface
        self._progress(40, "Configuring monitor interface...")
        configure_monitor_interface(self.answers['network.monitor_interface'])

        # Step 5: Run SO setup
        self._progress(50, "Running Security Onion setup (this may take a while)...")
        run_so_setup(self.answers)

        # Step 6: Configure SIEM forwarding
        self._progress(80, "Configuring SIEM forwarding...")
        configure_siem_forwarding(self.answers)

        # Step 7: Mark complete
        self._progress(100, "Setup complete!")
        mark_setup_complete()

        if self.d:
            self.d.gauge_stop()

    def _progress(self, percent: int, message: str):
        self.logger.info("[%d%%] %s", percent, message)
        if self.d:
            self.d.gauge_update(percent, message)

    def _show_complete(self):
        msg = (
            "CodeRed NDR setup is complete!\n\n"
            "The sensor is now configured and services are starting.\n"
            "You can log in as 'sensoradmin' for the restricted\n"
            "management menu.\n\n"
            "The system will reboot in 10 seconds."
        )
        if self.d:
            self.d.msgbox(msg, height=14, width=60)
        else:
            print(f"\n{msg}")

    def _show_error(self, message: str):
        if self.d:
            self.d.msgbox(f"Error: {message}", height=8, width=50)
        else:
            print(f"Error: {message}")


def main():
    setup_logging()

    # Must run as root
    if os.geteuid() != 0:
        print("Error: First-boot wizard must run as root.", file=sys.stderr)
        sys.exit(1)

    wizard = Wizard()
    sys.exit(wizard.run())


if __name__ == '__main__':
    main()

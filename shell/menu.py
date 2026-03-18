#!/usr/bin/env python3
"""CodeRed NDR - Restricted Management Shell.

This is the only interface available to the 'sensoradmin' user.
No escape to bash is possible. All actions are audited.
"""

import logging
import os
import sys
import signal
from datetime import datetime

try:
    import dialog
    HAS_DIALOG = True
except ImportError:
    HAS_DIALOG = False

from actions import (
    get_sensor_status, get_interface_status, get_forwarding_status,
    get_disk_usage, get_system_info, restart_services,
    restart_single_service, view_logs, reboot_system, shutdown_system,
)

AUDIT_LOG = '/var/log/codered/audit.log'
audit_logger = None


def setup_audit_logging():
    global audit_logger
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    audit_logger = logging.getLogger('codered.audit')
    audit_logger.setLevel(logging.INFO)
    handler = logging.FileHandler(AUDIT_LOG)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s AUDIT [%(name)s] user=sensoradmin action=%(message)s'
    ))
    audit_logger.addHandler(handler)


def audit(action: str):
    """Log an audited user action."""
    if audit_logger:
        audit_logger.info(action)


def disable_signals():
    """Prevent escape via signals."""
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)  # Ctrl+Z
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)  # Ctrl+\


class RestrictedMenu:
    """Dialog-based restricted management menu."""

    MENU_CHOICES = [
        ('status', 'View sensor service status'),
        ('interfaces', 'View network interfaces'),
        ('forwarding', 'View log forwarding status'),
        ('disk', 'View disk usage'),
        ('sysinfo', 'View system information'),
        ('restart-all', 'Restart all services'),
        ('restart-one', 'Restart a specific service'),
        ('logs', 'View recent logs'),
        ('reboot', 'Reboot sensor'),
        ('shutdown', 'Shut down sensor'),
    ]

    def __init__(self):
        if HAS_DIALOG:
            self.d = dialog.Dialog(dialog='dialog')
            self.d.set_background_title('CodeRed NDR Management')
        else:
            self.d = None

    def run(self):
        """Main menu loop - never exits to shell."""
        disable_signals()
        setup_audit_logging()
        audit("login")

        while True:
            try:
                choice = self._show_main_menu()
                if choice is None:
                    # User pressed Cancel/Escape - show exit confirmation
                    if self._confirm_logout():
                        audit("logout")
                        os._exit(0)
                    continue

                audit(f"selected:{choice}")
                self._handle_choice(choice)

            except KeyboardInterrupt:
                # Ctrl+C - just go back to menu
                continue
            except Exception as e:
                self._show_output(f"Error: {e}")

    def _show_main_menu(self) -> str | None:
        if self.d:
            code, choice = self.d.menu(
                "Select an action:",
                choices=self.MENU_CHOICES,
                height=20, width=60, menu_height=12,
            )
            return choice if code == self.d.OK else None
        else:
            return self._text_menu()

    def _text_menu(self) -> str | None:
        print("\n" + "=" * 50)
        print("  CodeRed NDR Management")
        print("=" * 50)
        for i, (key, desc) in enumerate(self.MENU_CHOICES, 1):
            print(f"  {i:2d}. {desc}")
        print(f"   0. Logout")
        print("=" * 50)

        try:
            choice = input("\nSelect [1-10]: ").strip()
            if choice == '0':
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(self.MENU_CHOICES):
                return self.MENU_CHOICES[idx][0]
        except (ValueError, IndexError):
            pass
        return ''

    def _handle_choice(self, choice: str):
        handlers = {
            'status': lambda: self._show_output(get_sensor_status()),
            'interfaces': lambda: self._show_output(get_interface_status()),
            'forwarding': lambda: self._show_output(get_forwarding_status()),
            'disk': lambda: self._show_output(get_disk_usage()),
            'sysinfo': lambda: self._show_output(get_system_info()),
            'restart-all': self._handle_restart_all,
            'restart-one': self._handle_restart_one,
            'logs': self._handle_logs,
            'reboot': self._handle_reboot,
            'shutdown': self._handle_shutdown,
        }

        handler = handlers.get(choice)
        if handler:
            handler()

    def _handle_restart_all(self):
        if self._confirm("Restart ALL sensor services?"):
            audit("restart-all:confirmed")
            self._show_output(restart_services())

    def _handle_restart_one(self):
        services = [
            ('zeek', 'Zeek (network metadata)'),
            ('suricata', 'Suricata (IDS/IPS)'),
            ('elastic-agent', 'Elastic Agent (log shipper)'),
            ('filebeat', 'Filebeat (log shipper)'),
        ]

        if self.d:
            code, svc = self.d.menu(
                "Select service to restart:",
                choices=services,
                height=14, width=55,
            )
            if code == self.d.OK:
                audit(f"restart-one:{svc}:confirmed")
                self._show_output(restart_single_service(svc))
        else:
            for i, (key, desc) in enumerate(services, 1):
                print(f"  {i}. {desc}")
            try:
                idx = int(input("Select: ").strip()) - 1
                if 0 <= idx < len(services):
                    svc = services[idx][0]
                    audit(f"restart-one:{svc}:confirmed")
                    self._show_output(restart_single_service(svc))
            except (ValueError, IndexError):
                pass

    def _handle_logs(self):
        log_types = [
            ('alerts', 'Suricata alerts (eve.json)'),
            ('zeek-dns', 'Zeek DNS log'),
            ('zeek-conn', 'Zeek connection log'),
            ('zeek-http', 'Zeek HTTP log'),
            ('system', 'System log'),
            ('codered', 'CodeRed setup log'),
        ]

        if self.d:
            code, log_type = self.d.menu(
                "Select log to view:",
                choices=log_types,
                height=15, width=55,
            )
            if code == self.d.OK:
                audit(f"view-logs:{log_type}")
                self._show_output(view_logs(log_type))
        else:
            for i, (key, desc) in enumerate(log_types, 1):
                print(f"  {i}. {desc}")
            try:
                idx = int(input("Select: ").strip()) - 1
                if 0 <= idx < len(log_types):
                    log_type = log_types[idx][0]
                    audit(f"view-logs:{log_type}")
                    self._show_output(view_logs(log_type))
            except (ValueError, IndexError):
                pass

    def _handle_reboot(self):
        if self._confirm("Reboot the sensor?"):
            audit("reboot:confirmed")
            self._show_output(reboot_system())

    def _handle_shutdown(self):
        if self._confirm("Shut down the sensor?\nThis will stop all monitoring!"):
            audit("shutdown:confirmed")
            self._show_output(shutdown_system())

    def _confirm(self, message: str) -> bool:
        if self.d:
            return self.d.yesno(message, height=8, width=50) == self.d.OK
        else:
            return input(f"{message} (y/N): ").strip().lower() == 'y'

    def _confirm_logout(self) -> bool:
        return self._confirm("Log out of the management console?")

    def _show_output(self, text: str):
        if self.d:
            self.d.scrollbox(text, height=24, width=78)
        else:
            print(text)
            input("\nPress Enter to continue...")


def main():
    # Verify we're running as the restricted user
    menu = RestrictedMenu()
    menu.run()


if __name__ == '__main__':
    main()

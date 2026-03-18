"""Tests for restricted shell actions."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from actions import get_system_info, restart_single_service


class TestActions:
    def test_get_system_info_returns_string(self):
        result = get_system_info()
        assert isinstance(result, str)
        assert "System Information" in result

    def test_restart_disallowed_service(self):
        result = restart_single_service('mysql')
        assert "not in allowed list" in result

    def test_restart_allowed_service_name(self):
        # Just verify it doesn't crash; the actual service won't be running
        result = restart_single_service('zeek')
        assert isinstance(result, str)

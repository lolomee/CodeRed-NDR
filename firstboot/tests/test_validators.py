"""Tests for firstboot input validators."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from validators import (
    validate_hostname, validate_ip, validate_netmask, validate_dns,
    validate_interface, validate_token, validate_endpoint, validate_port,
)


class TestValidateHostname:
    def test_valid_simple(self):
        assert validate_hostname('sensor-01')[0] is True

    def test_valid_fqdn(self):
        assert validate_hostname('sensor.corp.local')[0] is True

    def test_empty(self):
        assert validate_hostname('')[0] is False

    def test_too_long(self):
        assert validate_hostname('a' * 254)[0] is False

    def test_starts_with_hyphen(self):
        assert validate_hostname('-invalid')[0] is False

    def test_special_chars(self):
        assert validate_hostname('sensor_01')[0] is False

    def test_single_char(self):
        assert validate_hostname('a')[0] is True


class TestValidateIP:
    def test_valid(self):
        assert validate_ip('10.0.0.1')[0] is True

    def test_valid_edge(self):
        assert validate_ip('255.255.255.255')[0] is True

    def test_empty(self):
        assert validate_ip('')[0] is False

    def test_invalid(self):
        assert validate_ip('999.0.0.1')[0] is False

    def test_text(self):
        assert validate_ip('not-an-ip')[0] is False


class TestValidateNetmask:
    def test_valid_dotted(self):
        assert validate_netmask('255.255.255.0')[0] is True

    def test_valid_cidr(self):
        assert validate_netmask('24')[0] is True

    def test_invalid_cidr(self):
        assert validate_netmask('33')[0] is False

    def test_invalid_mask(self):
        assert validate_netmask('255.255.0.255')[0] is False

    def test_empty(self):
        assert validate_netmask('')[0] is False


class TestValidateDNS:
    def test_single(self):
        assert validate_dns('8.8.8.8')[0] is True

    def test_multiple(self):
        assert validate_dns('8.8.8.8,8.8.4.4')[0] is True

    def test_with_spaces(self):
        assert validate_dns('8.8.8.8, 8.8.4.4')[0] is True

    def test_invalid(self):
        assert validate_dns('not-dns')[0] is False

    def test_empty(self):
        assert validate_dns('')[0] is False


class TestValidateInterface:
    def test_valid_eth(self):
        assert validate_interface('eth0')[0] is True

    def test_valid_ens(self):
        assert validate_interface('ens34')[0] is True

    def test_empty(self):
        assert validate_interface('')[0] is False

    def test_starts_with_number(self):
        assert validate_interface('0eth')[0] is False


class TestValidateToken:
    def test_empty_allowed(self):
        assert validate_token('')[0] is True

    def test_valid(self):
        assert validate_token('cr-tok-abc123')[0] is True

    def test_too_short(self):
        assert validate_token('ab')[0] is False


class TestValidateEndpoint:
    def test_ip(self):
        assert validate_endpoint('10.0.0.1')[0] is True

    def test_hostname(self):
        assert validate_endpoint('siem.company.com')[0] is True

    def test_empty(self):
        assert validate_endpoint('')[0] is False


class TestValidatePort:
    def test_valid(self):
        assert validate_port('9200')[0] is True

    def test_zero(self):
        assert validate_port('0')[0] is False

    def test_too_high(self):
        assert validate_port('99999')[0] is False

    def test_text(self):
        assert validate_port('abc')[0] is False

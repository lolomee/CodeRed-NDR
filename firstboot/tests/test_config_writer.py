"""Tests for config writer."""

import os
import sys
import tempfile
import configparser

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config_writer


class TestConfigWriter:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        config_writer.CONF_DIR = self.tmpdir
        config_writer.CONF_FILE = os.path.join(self.tmpdir, 'sensor.conf')
        config_writer.DEFAULTS_FILE = os.path.join(self.tmpdir, 'codered.defaults')
        config_writer.SETUP_SENTINEL = os.path.join(self.tmpdir, '.setup-complete')

    def test_write_and_read(self):
        answers = {
            'sensor.hostname': 'test-sensor',
            'network.mgmt_ip': '10.0.0.5',
            'network.mgmt_mode': 'static',
        }
        path = config_writer.write_config(answers)
        assert os.path.exists(path)

        config = config_writer.read_config()
        assert config.get('sensor', 'hostname') == 'test-sensor'
        assert config.get('network', 'mgmt_ip') == '10.0.0.5'

    def test_setup_sentinel(self):
        assert config_writer.is_setup_complete() is False
        config_writer.mark_setup_complete()
        assert config_writer.is_setup_complete() is True

    def test_get_config_value(self):
        answers = {'sensor.hostname': 'my-sensor'}
        config_writer.write_config(answers)
        assert config_writer.get_config_value('sensor', 'hostname') == 'my-sensor'
        assert config_writer.get_config_value('sensor', 'missing', 'default') == 'default'

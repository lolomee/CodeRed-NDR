"""Shared pytest configuration."""

import sys
import os

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firstboot'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shell'))

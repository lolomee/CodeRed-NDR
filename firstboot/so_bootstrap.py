"""Bridge between wizard output and Security Onion setup."""

import logging
import os
import subprocess
import time

logger = logging.getLogger('codered.bootstrap')

SO_SETUP_CMD = '/usr/sbin/so-setup'
SO_ALLOW_CMD = '/usr/sbin/so-allow'
SO_SALT_DIR = '/opt/so/saltstack/local'
SO_CONF_DIR = '/opt/so/conf'


def generate_so_answers(config: dict) -> dict:
    """Generate Security Onion setup answers from CodeRed config.

    Args:
        config: Flat dict with 'section.key' style keys from wizard answers.

    Returns:
        Dict suitable for SO setup automation.
    """
    return {
        'HOSTNAME': config.get('sensor.hostname', 'codered-sensor'),
        'INTERFACE': config.get('network.monitor_interface', 'ens34'),
        'MGMT_INTERFACE': config.get('network.mgmt_interface', 'ens32'),
        'NODESETUP': 'SENSOR',
        'NSMSETUP': 'ADVANCED',
        'ZEEK_PROCESSES': config.get('zeek.workers', 'auto'),
        'SURICATA_ENABLED': 'yes',
        'ZEEK_ENABLED': 'yes',
    }


def write_so_setup_conf(answers: dict) -> str:
    """Write SO setup configuration file."""
    conf_path = os.path.join(SO_CONF_DIR, 'setup-answers.conf')
    os.makedirs(SO_CONF_DIR, exist_ok=True)

    with open(conf_path, 'w') as f:
        for key, value in answers.items():
            f.write(f'{key}={value}\n')

    os.chmod(conf_path, 0o600)
    logger.info("SO setup answers written to %s", conf_path)
    return conf_path


def run_so_setup(config: dict) -> bool:
    """Run Security Onion sensor setup in non-interactive mode.

    This function handles the SO-specific setup steps:
    1. Write setup answers
    2. Run so-setup in automated mode
    3. Wait for services to start
    4. Apply CodeRed Salt states
    """
    logger.info("Starting Security Onion sensor setup...")

    # Generate and write setup answers
    answers = generate_so_answers(config)
    conf_path = write_so_setup_conf(answers)

    # Check if SO is already set up
    if os.path.exists('/opt/so/state/setup_complete'):
        logger.info("Security Onion already set up, applying CodeRed overlay only")
        return apply_codered_states()

    # Run so-setup
    if os.path.exists(SO_SETUP_CMD):
        try:
            logger.info("Running so-setup (this may take 10-30 minutes)...")
            result = subprocess.run(
                [SO_SETUP_CMD, '--automated', '--config', conf_path],
                capture_output=True, text=True, timeout=3600
            )
            if result.returncode != 0:
                logger.error("so-setup failed: %s", result.stderr)
                return False
            logger.info("so-setup completed successfully")
        except subprocess.TimeoutExpired:
            logger.error("so-setup timed out after 60 minutes")
            return False
    else:
        logger.warning("so-setup not found at %s, skipping SO setup", SO_SETUP_CMD)

    # Apply CodeRed custom Salt states
    return apply_codered_states()


def apply_codered_states() -> bool:
    """Apply CodeRed-specific Salt states on top of SO."""
    logger.info("Applying CodeRed Salt states...")
    try:
        result = subprocess.run(
            ['salt-call', '--local', 'state.apply', 'codered'],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            logger.error("Salt state apply failed: %s", result.stderr)
            return False
        logger.info("CodeRed Salt states applied successfully")
        return True
    except subprocess.TimeoutExpired:
        logger.error("Salt state apply timed out")
        return False
    except FileNotFoundError:
        logger.error("salt-call not found. Is Salt installed?")
        return False


def configure_siem_forwarding(config: dict) -> bool:
    """Configure log forwarding to external SIEM."""
    backend = config.get('forwarding.backend', 'elastic-agent')
    endpoint = config.get('forwarding.siem_endpoint', '')
    port = config.get('forwarding.siem_port', '9200')
    token = config.get('forwarding.siem_token', '')

    if not endpoint:
        logger.warning("No SIEM endpoint configured, skipping forwarding setup")
        return True

    logger.info("Configuring %s forwarding to %s:%s", backend, endpoint, port)

    # Write forwarding pillar
    pillar_dir = os.path.join(SO_SALT_DIR, 'pillar', 'codered')
    os.makedirs(pillar_dir, exist_ok=True)

    pillar_path = os.path.join(pillar_dir, 'forwarding.sls')
    with open(pillar_path, 'w') as f:
        f.write("codered:\n")
        f.write("  forwarding:\n")
        f.write(f"    backend: {backend}\n")
        f.write(f"    siem_endpoint: {endpoint}\n")
        f.write(f"    siem_port: {port}\n")
        f.write(f"    siem_protocol: {config.get('forwarding.siem_protocol', 'https')}\n")
        f.write(f"    siem_token: '{token}'\n")
        f.write(f"    siem_verify_ssl: {config.get('forwarding.siem_verify_ssl', 'yes')}\n")

    os.chmod(pillar_path, 0o600)
    logger.info("Forwarding pillar written to %s", pillar_path)

    # Apply the forwarding state
    try:
        result = subprocess.run(
            ['salt-call', '--local', 'state.apply', 'codered.forwarding'],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            logger.error("Forwarding state failed: %s", result.stderr)
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error("Failed to apply forwarding state: %s", e)
        return False

import pytest
import subprocess
from pathlib import Path


@pytest.fixture(scope="session")
def ensure_rsa_ca():
    """Fixture to ensure RSA CA exists before running tests"""
    rsa_cert = Path("pki/certs/ca.cert.pem")
    if not rsa_cert.exists():
        # Create RSA CA if it doesn't exist
        subprocess.run([
            'python', '-m', 'micropki.cli', 'ca', 'init',
            '--subject', '/CN=Test RSA CA',
            '--key-type', 'rsa',
            '--key-size', '4096',
            '--passphrase-file', 'secrets/pass.txt',
            '--out-dir', './pki',
            '--validity-days', '365'
        ], check=True)
    return rsa_cert


@pytest.fixture(scope="session")
def ensure_ecc_ca():
    """Fixture to ensure ECC CA exists before running tests"""
    ecc_cert = Path("pki-ecc/certs/ca.cert.pem")
    if not ecc_cert.exists():
        # Create ECC CA if it doesn't exist
        subprocess.run([
            'python', '-m', 'micropki.cli', 'ca', 'init',
            '--subject', '/CN=Test ECC CA',
            '--key-type', 'ecc',
            '--key-size', '384',
            '--passphrase-file', 'secrets/pass.txt',
            '--out-dir', './pki-ecc',
            '--validity-days', '365'
        ], check=True)
    return ecc_cert
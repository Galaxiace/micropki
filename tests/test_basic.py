import pytest
from pathlib import Path
import tempfile
import os
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, generate_serial_number,
    compute_ski, create_dn_from_components, encrypt_private_key
)
from micropki.logger import MicroPKILogger


def test_rsa_key_generation():
    """Test RSA key generation"""
    key = generate_rsa_key(4096)
    assert key is not None
    assert key.key_size == 4096


def test_ecc_key_generation():
    """Test ECC key generation"""
    key = generate_ecc_key(384)
    assert key is not None
    assert key.curve.name == 'secp384r1'


def test_serial_number_generation():
    """Test serial number generation - must be positive and <= 159 bits"""
    for i in range(100):
        sn = generate_serial_number()
        assert sn > 0, f"Serial number must be positive, got {sn}"
        bits = sn.bit_length()
        assert bits <= 159, f"Serial number has {bits} bits, should be <= 159 (iteration {i})"
        assert bits >= 20, f"Serial number too small: {bits} bits"  # Минимум 20 бит для безопасности


def test_compute_ski():
    """Test Subject Key Identifier computation"""
    key = generate_rsa_key(4096)
    ski = compute_ski(key.public_key())
    assert len(ski) == 20  # SHA-1 is 20 bytes


def test_create_dn_from_components():
    """Test DN creation from components"""
    components = {
        'CN': 'Test CA',
        'O': 'MicroPKI',
        'C': 'RU'
    }
    name = create_dn_from_components(components)
    name_str = name.rfc4514_string()
    assert 'CN=Test CA' in name_str
    assert 'O=MicroPKI' in name_str
    assert 'C=RU' in name_str


def test_encrypt_private_key():
    """Test private key encryption"""
    key = generate_rsa_key(4096)
    passphrase = b'testpassphrase'
    encrypted = encrypt_private_key(key, passphrase)

    assert encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')

    # Test decryption
    loaded_key = serialization.load_pem_private_key(
        encrypted,
        password=passphrase,
        backend=default_backend()
    )
    assert loaded_key is not None


def test_logger_creation():
    """Test logger creation"""
    logger = MicroPKILogger(log_file=None)
    assert logger is not None

    with tempfile.NamedTemporaryFile() as tmp:
        file_logger = MicroPKILogger(log_file=tmp.name)
        file_logger.info("Test message")
        assert Path(tmp.name).exists()


def test_serial_number_guaranteed_bits():
    """Test that serial number meets requirements"""
    for _ in range(100):
        sn = generate_serial_number()
        assert sn > 0
        bits = sn.bit_length()
        assert bits <= 159, f"Serial number has {bits} bits, should be <= 159"
        assert bits >= 20, f"Serial number too small: {bits} bits"
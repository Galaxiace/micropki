"""
Tests for private key and certificate matching (TEST-2 and TEST-3).
"""

import pytest
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import tempfile
import os

# Пути к тестовым файлам (будут созданы тестами)
TEST_PASSPHRASE = b"mySecurePassword123"
TEST_PASSPHRASE_WRONG = b"wrongPassword123"


def get_test_cert_path():
    """Get path to test certificate"""
    cert_path = Path("pki/certs/ca.cert.pem")
    if not cert_path.exists():
        pytest.skip("Test certificate not found. Run 'make run-rsa' first.")
    return cert_path


def get_test_key_path():
    """Get path to test private key"""
    key_path = Path("pki/private/ca.key.pem")
    if not key_path.exists():
        pytest.skip("Test private key not found. Run 'make run-rsa' first.")
    return key_path


# ========== TEST-2: Private Key & Certificate Matching ==========

def test_private_key_matches_certificate():
    """
    TEST-2: Verify that private key corresponds to certificate's public key.

    This test:
    1. Loads the certificate and extracts its public key
    2. Loads the encrypted private key (with correct passphrase)
    3. Signs test data with private key
    4. Verifies the signature with certificate's public key
    """
    # Get test files
    cert_path = get_test_cert_path()
    key_path = get_test_key_path()

    # Load certificate
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Load encrypted private key
    with open(key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Decrypt private key with correct passphrase
    private_key = serialization.load_pem_private_key(
        encrypted_key_data,
        password=TEST_PASSPHRASE,
        backend=default_backend()
    )

    # Test data
    test_message = b"MicroPKI Test Message for Signature Verification"

    # Sign with private key
    if isinstance(private_key, rsa.RSAPrivateKey):
        # RSA signing
        signature = private_key.sign(
            test_message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # Verify with public key from certificate
        cert.public_key().verify(
            signature,
            test_message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        # ECC signing
        signature = private_key.sign(
            test_message,
            ec.ECDSA(hashes.SHA384())
        )
        # Verify with public key from certificate
        cert.public_key().verify(
            signature,
            test_message,
            ec.ECDSA(hashes.SHA384())
        )
    else:
        pytest.fail(f"Unknown key type: {type(private_key)}")

    # If we got here without exceptions, the test passed
    assert True, "Private key successfully signed and verified with certificate"


def test_private_key_matches_certificate_ecc():
    """
    TEST-2: Same test but for ECC certificate.
    """
    ecc_cert_path = Path("pki-ecc/certs/ca.cert.pem")
    ecc_key_path = Path("pki-ecc/private/ca.key.pem")

    if not ecc_cert_path.exists() or not ecc_key_path.exists():
        pytest.skip("ECC test certificate not found. Run ECC creation first.")

    # Load certificate
    with open(ecc_cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Load encrypted private key
    with open(ecc_key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Decrypt private key
    private_key = serialization.load_pem_private_key(
        encrypted_key_data,
        password=TEST_PASSPHRASE,
        backend=default_backend()
    )

    # Test data
    test_message = b"MicroPKI ECC Test Message"

    # Sign and verify
    signature = private_key.sign(
        test_message,
        ec.ECDSA(hashes.SHA384())
    )

    cert.public_key().verify(
        signature,
        test_message,
        ec.ECDSA(hashes.SHA384())
    )

    assert True, "ECC private key successfully signed and verified with certificate"


# ========== TEST-3: Encrypted Key Loading ==========

def test_load_encrypted_key_with_correct_passphrase():
    """
    TEST-3: Verify that encrypted private key can be decrypted with correct passphrase.
    """
    key_path = get_test_key_path()

    # Load encrypted private key
    with open(key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Try to load with correct passphrase
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_key_data,
            password=TEST_PASSPHRASE,
            backend=default_backend()
        )
        assert private_key is not None
        assert isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
    except Exception as e:
        pytest.fail(f"Failed to load key with correct passphrase: {e}")


def test_load_encrypted_key_with_wrong_passphrase():
    """
    TEST-3: Verify that loading encrypted key with wrong passphrase fails.
    """
    key_path = get_test_key_path()

    # Load encrypted private key
    with open(key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Try to load with wrong passphrase - should raise exception
    with pytest.raises(Exception) as excinfo:
        serialization.load_pem_private_key(
            encrypted_key_data,
            password=TEST_PASSPHRASE_WRONG,
            backend=default_backend()
        )

    # Verify it's the right kind of error
    assert "password" in str(excinfo.value).lower() or "decrypt" in str(excinfo.value).lower()


def test_load_encrypted_key_without_password():
    """
    TEST-3: Verify that loading encrypted key without password fails.
    """
    key_path = get_test_key_path()

    with open(key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Try to load without password - should raise exception
    with pytest.raises(TypeError) or pytest.raises(ValueError):
        # Some versions of cryptography require password for encrypted keys
        serialization.load_pem_private_key(
            encrypted_key_data,
            password=None,
            backend=default_backend()
        )


def test_key_operations_after_loading():
    """
    TEST-3: After loading the key, ensure it can perform crypto operations.
    """
    key_path = get_test_key_path()

    with open(key_path, 'rb') as f:
        encrypted_key_data = f.read()

    # Load key
    private_key = serialization.load_pem_private_key(
        encrypted_key_data,
        password=TEST_PASSPHRASE,
        backend=default_backend()
    )

    # Test that key can sign data
    test_data = b"Test data for signing"

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        assert len(signature) > 0
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(
            test_data,
            ec.ECDSA(hashes.SHA384())
        )
        assert len(signature) > 0

    assert True, "Key can perform signing operations after loading"


# ========== Additional helper tests ==========

def test_key_file_permissions():
    """
    Test that key file has correct permissions (600).
    This is a security requirement from KEY-3.
    """
    key_path = get_test_key_path()

    # Check file permissions on Unix-like systems
    if os.name == 'posix':
        stat = os.stat(key_path)
        permissions = stat.st_mode & 0o777
        assert permissions == 0o600, f"Key file has permissions {oct(permissions)}, should be 0o600"


def test_private_directory_permissions():
    """
    Test that private directory has correct permissions (700).
    This is a security requirement from KEY-3.
    """
    private_dir = Path("pki/private")

    if private_dir.exists() and os.name == 'posix':
        stat = os.stat(private_dir)
        permissions = stat.st_mode & 0o777
        assert permissions == 0o700, f"Private directory has permissions {oct(permissions)}, should be 0o700"
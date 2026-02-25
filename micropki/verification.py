"""
Certificate verification utilities for MicroPKI.
"""

import subprocess
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
import os


def verify_with_openssl(cert_path: str, logger) -> bool:
    """
    Verify certificate using OpenSSL (TEST-1 requirement).
    """
    try:
        # Проверка 1: Показать информацию о сертификате
        logger.info(f"Verifying certificate: {cert_path}")

        # Проверка с OpenSSL
        result = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-text', '-noout'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info("Certificate format is valid")
            # Выводим основную информацию
            for line in result.stdout.split('\n'):
                if 'Subject:' in line or 'Issuer:' in line or 'Not Before' in line:
                    logger.info(line.strip())
        else:
            logger.error(f"OpenSSL verification failed: {result.stderr}")
            return False

        # Проверка 2: Self-consistency (самоподписанный)
        verify_cmd = ['openssl', 'verify', '-CAfile', cert_path, cert_path]
        result = subprocess.run(verify_cmd, capture_output=True, text=True)

        if result.returncode == 0 and 'OK' in result.stdout:
            logger.info("✓ Certificate is self-consistent (openssl verify OK)")
            return True
        else:
            logger.error(f"✗ Self-consistency check failed: {result.stderr}")
            return False

    except FileNotFoundError:
        logger.error("OpenSSL not found. Please install OpenSSL.")
        return False


def verify_extensions(cert_path: str, logger) -> bool:
    """
    Verify X.509v3 extensions (PKI-2 requirements).
    """
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Проверка Basic Constraints
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        if basic_constraints.value.ca:
            logger.info("✓ Basic Constraints: CA=TRUE")
            if basic_constraints.critical:
                logger.info("  ✓ Extension is CRITICAL (as required)")
        else:
            logger.error("✗ Basic Constraints: CA should be TRUE")
            return False

        # Проверка Key Usage
        key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        if key_usage.value.key_cert_sign and key_usage.value.crl_sign:
            logger.info("✓ Key Usage: keyCertSign and cRLSign present")
            if key_usage.critical:
                logger.info("  ✓ Extension is CRITICAL (as required)")
        else:
            logger.error("✗ Key Usage: missing keyCertSign or cRLSign")
            return False

        # Проверка SKI
        ski = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        logger.info(f"✓ Subject Key Identifier: {ski.value.digest.hex()[:16]}...")

        # Проверка AKI
        aki = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        logger.info(f"✓ Authority Key Identifier: {aki.value.key_identifier.hex()[:16]}...")

        # Проверка что SKI == AKI (для self-signed)
        if ski.value.digest == aki.value.key_identifier:
            logger.info("✓ SKI matches AKI (self-signed)")
        else:
            logger.warning("⚠ SKI differs from AKI (should match for self-signed)")

        return True

    except Exception as e:
        logger.error(f"Extension verification failed: {e}")
        return False


def verify_certificate(cert_path: str, logger) -> bool:
    """
    Main verification function.
    """
    logger.info("=== MicroPKI Certificate Verification ===")

    # Проверка расширений
    if not verify_extensions(cert_path, logger):
        return False

    # Проверка с OpenSSL
    if not verify_with_openssl(cert_path, logger):
        return False

    logger.info("=== Verification PASSED ===")
    return True
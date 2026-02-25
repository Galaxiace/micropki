from pathlib import Path
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, generate_serial_number,
    compute_ski, create_dn_from_components, encrypt_private_key
)


def create_policy_file(out_dir: Path, subject_dn: str, serial_number: int,
                       not_before: datetime, not_after: datetime,
                       key_type: str, key_size: int, logger) -> None:
    """Create the policy.txt file"""
    policy_content = f"""Certificate Policy Document - MicroPKI Root CA
===========================================

CA Name: {subject_dn}
Certificate Serial Number (hex): {format(serial_number, 'x')}
Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  Not After: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm: {key_type.upper()}-{key_size}
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

This certificate serves as the root of trust for the MicroPKI infrastructure.
"""
    policy_path = out_dir / 'policy.txt'
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(policy_content)

    logger.info(f"Policy document created: {policy_path}")


def initialize_root_ca(subject_components: dict, key_type: str, key_size: int,
                       passphrase: bytes, out_dir: str, validity_days: int,
                       logger) -> bool:
    """Initialize a new Root CA"""
    try:
        logger.info("Starting Root CA initialization")

        # Create output directories
        out_path = Path(out_dir)
        private_dir = out_path / 'private'
        certs_dir = out_path / 'certs'

        private_dir.mkdir(parents=True, exist_ok=True)
        certs_dir.mkdir(parents=True, exist_ok=True)

        # Set secure permissions on private directory
        os.chmod(private_dir, 0o700)
        logger.info(f"Created directories with secure permissions")

        # Generate key pair
        logger.info(f"Generating {key_type.upper()}-{key_size} key pair")
        if key_type == 'rsa':
            private_key = generate_rsa_key(key_size)
        else:
            private_key = generate_ecc_key(key_size)
        logger.info("Key generation completed successfully")

        # Create subject name
        subject = create_dn_from_components(subject_components)

        # Generate serial number
        serial_number = generate_serial_number()

        # Set validity period
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)

        # Compute SKI
        ski = compute_ski(private_key.public_key())

        # Build certificate
        logger.info("Building X.509 certificate")
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(subject)  # Self-signed
        cert_builder = cert_builder.not_valid_before(not_before)
        cert_builder = cert_builder.not_valid_after(not_after)
        cert_builder = cert_builder.serial_number(serial_number)
        cert_builder = cert_builder.public_key(private_key.public_key())

        # Add extensions
        # Basic Constraints: CA=true (critical)
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

        # Key Usage: keyCertSign, cRLSign (critical)
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Subject Key Identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )

        # Authority Key Identifier (same as SKI for self-signed)
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            ),
            critical=False
        )

        # Sign certificate
        if key_type == 'rsa':
            signature_hash = hashes.SHA256()
        else:
            signature_hash = hashes.SHA384()

        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=signature_hash,
            backend=default_backend()
        )
        logger.info("Certificate signing completed")

        # Save encrypted private key
        encrypted_key = encrypt_private_key(private_key, passphrase)
        key_path = private_dir / 'ca.key.pem'
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)

        # Set secure permissions on key file
        os.chmod(key_path, 0o600)
        logger.info(f"Encrypted private key saved: {key_path}")

        # Save certificate
        cert_path = certs_dir / 'ca.cert.pem'
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Certificate saved: {cert_path}")

        # Create policy document
        create_policy_file(
            out_path,
            subject.rfc4514_string(),
            serial_number,
            not_before,
            not_after,
            key_type,
            key_size,
            logger
        )
        logger.info(f"Policy document created: {out_path / 'policy.txt'}")

        return True

    except Exception as e:
        logger.error(f"CA initialization failed: {e}")
        return False
from pathlib import Path
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, generate_serial_number,
    compute_ski, create_dn_from_components, encrypt_private_key
)
from micropki.csr import (
    generate_intermediate_csr, sign_intermediate_csr, parse_san_strings,
    sign_external_csr
)
from micropki.templates import get_template
from micropki.chain import validate_chain, verify_chain_with_openssl, load_certificate, print_chain_info


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


def update_policy_file_with_intermediate(
        out_dir: Path,
        subject_dn: str,
        serial_number: int,
        not_before: datetime,
        not_after: datetime,
        key_type: str,
        key_size: int,
        pathlen: int,
        issuer_dn: str,
        logger
) -> None:
    """Update policy.txt with Intermediate CA information"""
    policy_path = out_dir / 'policy.txt'

    if not policy_path.exists():
        logger.warning(f"Policy file not found at {policy_path}, creating new one")
        policy_content = "MicroPKI Policy Document\n========================\n\n"
    else:
        with open(policy_path, 'r', encoding='utf-8') as f:
            policy_content = f.read()

    # Append Intermediate CA section
    policy_content += f"""
Intermediate CA Information
===========================
Created: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

Subject DN: {subject_dn}
Serial Number (hex): {format(serial_number, 'x')}
Validity Period:
  Not Before: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}
  Not After: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}
Key Algorithm: {key_type.upper()}-{key_size}
Path Length Constraint: {pathlen}
Issuer (Root CA): {issuer_dn}

"""
    with open(policy_path, 'w', encoding='utf-8') as f:
        f.write(policy_content)

    logger.info(f"Policy document updated with Intermediate CA info: {policy_path}")


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


def issue_intermediate_ca(
        root_cert_path: Path,
        root_key_path: Path,
        root_passphrase: bytes,
        subject_components: dict,
        key_type: str,
        key_size: int,
        passphrase: bytes,
        out_dir: str,
        validity_days: int,
        pathlen: int,
        logger
) -> bool:
    """Issue an Intermediate CA certificate signed by the Root CA"""
    try:
        logger.info("Starting Intermediate CA issuance")

        # Create output directories
        out_path = Path(out_dir)
        private_dir = out_path / 'private'
        certs_dir = out_path / 'certs'
        csrs_dir = out_path / 'certs' / 'csrs'

        private_dir.mkdir(parents=True, exist_ok=True)
        certs_dir.mkdir(parents=True, exist_ok=True)
        csrs_dir.mkdir(parents=True, exist_ok=True)

        # Set secure permissions on private directory
        os.chmod(private_dir, 0o700)
        logger.info(f"Created directories with secure permissions")

        # Load Root CA certificate and key
        logger.info(f"Loading Root CA from: {root_cert_path}")
        with open(root_cert_path, 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        logger.info(f"Loading Root CA private key from: {root_key_path}")
        with open(root_key_path, 'rb') as f:
            root_key_data = f.read()
        root_private_key = serialization.load_pem_private_key(
            root_key_data,
            password=root_passphrase,
            backend=default_backend()
        )

        # Generate Intermediate CA CSR
        logger.info(f"Generating Intermediate CA CSR with subject: {subject_components}")
        intermediate_private_key, csr = generate_intermediate_csr(
            subject_components=subject_components,
            key_type=key_type,
            key_size=key_size,
            pathlen=pathlen,
            logger=logger
        )

        # Save CSR
        csr_path = csrs_dir / 'intermediate.csr.pem'
        with open(csr_path, 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Intermediate CA CSR saved: {csr_path}")

        # Sign Intermediate CSR with Root CA
        logger.info("Signing Intermediate CA CSR with Root CA")
        serial_number = generate_serial_number()
        intermediate_cert = sign_intermediate_csr(
            csr=csr,
            root_cert=root_cert,
            root_private_key=root_private_key,
            validity_days=validity_days,
            pathlen=pathlen,
            serial_number=serial_number,
            logger=logger
        )

        # Save encrypted Intermediate CA private key
        encrypted_key = encrypt_private_key(intermediate_private_key, passphrase)
        key_path = private_dir / 'intermediate.key.pem'
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)
        os.chmod(key_path, 0o600)
        logger.info(f"Encrypted Intermediate CA private key saved: {key_path}")

        # Save Intermediate CA certificate
        cert_path = certs_dir / 'intermediate.cert.pem'
        with open(cert_path, 'wb') as f:
            f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Intermediate CA certificate saved: {cert_path}")

        # Update policy document
        update_policy_file_with_intermediate(
            out_path,
            csr.subject.rfc4514_string(),
            serial_number,
            intermediate_cert.not_valid_before_utc,
            intermediate_cert.not_valid_after_utc,
            key_type,
            key_size,
            pathlen,
            root_cert.subject.rfc4514_string(),
            logger
        )

        logger.info(f"Intermediate CA issuance completed successfully")
        logger.info(f"  Subject: {csr.subject.rfc4514_string()}")
        logger.info(f"  Serial: {format(serial_number, 'x')}")
        logger.info(f"  Validity: {intermediate_cert.not_valid_before_utc} to {intermediate_cert.not_valid_after_utc}")

        return True

    except Exception as e:
        logger.error(f"Intermediate CA issuance failed: {e}")
        return False


def issue_end_entity_certificate(
        ca_cert_path: Path,
        ca_key_path: Path,
        ca_passphrase: bytes,
        template_name: str,
        subject_components: dict,
        san_strings: List[str],
        out_dir: str,
        validity_days: int,
        csr_path: Optional[Path] = None,
        logger=None
) -> bool:
    """Issue an end-entity certificate signed by the Intermediate CA"""
    try:
        logger.info(f"Starting end-entity certificate issuance using template: {template_name}")

        # Create output directories
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Load CA certificate and key
        logger.info(f"Loading CA certificate from: {ca_cert_path}")
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        logger.info(f"Loading CA private key from: {ca_key_path}")
        with open(ca_key_path, 'rb') as f:
            ca_key_data = f.read()
        ca_private_key = serialization.load_pem_private_key(
            ca_key_data,
            password=ca_passphrase,
            backend=default_backend()
        )

        # Get template
        template = get_template(template_name)

        # Parse SAN entries
        san_entries = []
        if san_strings:
            san_entries = parse_san_strings(san_strings)

            # Validate SAN entries against template
            errors = template.validate_san_entries(san_entries)
            if errors:
                for error in errors:
                    logger.error(f"SAN validation error: {error}")
                return False

        # Check for required SANs
        if template.get_required_san_types() and not san_entries:
            logger.error(f"Template {template_name} requires at least one SAN")
            return False

        # Create subject name
        subject = create_dn_from_components(subject_components)

        # Generate serial number
        serial_number = generate_serial_number()

        # Set validity period
        not_before = datetime.now(timezone.utc)
        not_after = not_before + timedelta(days=validity_days)

        # Compute SKI from CA's key for AKI
        ca_ski = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value.digest

        if csr_path:
            # Sign external CSR
            logger.info(f"Signing external CSR from: {csr_path}")
            certificate = sign_external_csr(
                csr_path=csr_path,
                ca_cert=ca_cert,
                ca_private_key=ca_private_key,
                template=template,
                validity_days=validity_days,
                san_entries=san_entries,
                logger=logger
            )
            # For CSR, private key is not saved
            private_key = None
        else:
            # Generate new key pair
            logger.info("Generating new key pair for end-entity")
            if isinstance(ca_private_key, rsa.RSAPrivateKey):
                # For consistency, use RSA-2048 for end-entity if CA is RSA
                private_key = generate_rsa_key(2048)
                signature_hash = hashes.SHA256()
            else:
                # Use ECC P-256 for end-entity if CA is ECC
                private_key = generate_ecc_key(256)
                signature_hash = hashes.SHA256()  # SHA256 with P-256 is fine

            # Compute SKI from new public key
            ski = compute_ski(private_key.public_key())

            # Build certificate
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(ca_cert.subject)
            cert_builder = cert_builder.not_valid_before(not_before)
            cert_builder = cert_builder.not_valid_after(not_after)
            cert_builder = cert_builder.serial_number(serial_number)
            cert_builder = cert_builder.public_key(private_key.public_key())

            # Add template extensions
            for extension in template.build_extensions(san_entries):
                cert_builder = cert_builder.add_extension(
                    extension.value,
                    critical=extension.critical
                )

            # Add SKI
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier(ski),
                critical=False
            )

            # Add AKI
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=ca_ski,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None
                ),
                critical=False
            )

            # Sign certificate
            certificate = cert_builder.sign(
                private_key=ca_private_key,
                algorithm=signature_hash,
                backend=default_backend()
            )

        # Generate filename from CN or first SAN
        cn_attr = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attr:
            base_name = cn_attr[0].value.replace(' ', '_').replace('*', 'wildcard')
        elif san_entries:
            # Use first SAN value as filename
            base_name = san_entries[0].value.replace(' ', '_').replace('*', 'wildcard')
        else:
            base_name = f"cert_{format(serial_number, 'x')}"

        # Save certificate
        cert_filename = f"{base_name}.cert.pem"
        cert_path = out_path / cert_filename
        with open(cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Certificate saved: {cert_path}")

        # KEY-7: Save private key if generated (not from CSR) - UNENCRYPTED with warning
        if private_key:
            key_filename = f"{base_name}.key.pem"
            key_path = out_path / key_filename

            # KEY-7: Save unencrypted private key (NoEncryption)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # Явно без шифрования
            )
            with open(key_path, 'wb') as f:
                f.write(key_pem)

            # Set secure permissions (0o600)
            os.chmod(key_path, 0o600)

            # KEY-7: Emit warning that private key is stored unencrypted
            logger.warning("=" * 60)
            logger.warning("WARNING: Private key is stored UNENCRYPTED!")
            logger.warning(f"Location: {key_path}")
            logger.warning("This key must be protected with appropriate file system permissions.")
            logger.warning("For production use, consider using encrypted keys or HSM.")
            logger.warning("=" * 60)
        else:
            logger.info("Certificate issued from CSR - no private key stored")

        # Log issuance
        logger.info(f"Certificate issued successfully:")
        logger.info(f"  Template: {template_name}")
        logger.info(f"  Subject: {subject.rfc4514_string()}")
        logger.info(f"  Serial: {format(serial_number, 'x')}")
        if san_entries:
            logger.info(f"  SANs: {', '.join(f'{e.type.value}:{e.value}' for e in san_entries)}")
        logger.info(f"  Validity: {not_before} to {not_after}")

        return True

    except Exception as e:
        logger.error(f"Certificate issuance failed: {e}")
        return False


def validate_certificate_chain(
        leaf_path: Path,
        intermediate_paths: List[Path],
        root_path: Path,
        logger
) -> bool:
    """Validate a certificate chain"""
    try:
        logger.info("Starting certificate chain validation")

        # Load certificates
        leaf_cert = load_certificate(leaf_path)
        intermediate_certs = [load_certificate(p) for p in intermediate_paths]
        root_cert = load_certificate(root_path)

        # Print chain info
        print_chain_info(leaf_cert, intermediate_certs, root_cert, logger)

        # Validate chain programmatically
        logger.info("Performing programmatic chain validation...")
        errors = validate_chain(leaf_cert, intermediate_certs, root_cert)

        if errors:
            logger.error("Chain validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            return False

        logger.info("✓ Programmatic chain validation passed")

        # Verify with OpenSSL
        logger.info("Verifying chain with OpenSSL...")
        success, output = verify_chain_with_openssl(
            leaf_path, intermediate_paths, root_path, logger
        )

        if success:
            logger.info("✓ OpenSSL chain verification passed")
            logger.debug(f"OpenSSL output: {output}")
            return True
        else:
            logger.error(f"✗ OpenSSL chain verification failed: {output}")
            return False

    except Exception as e:
        logger.error(f"Chain validation failed with exception: {e}")
        return False
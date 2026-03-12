from pathlib import Path
from typing import Optional, Tuple, Union, List
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, compute_ski,
    create_dn_from_components, encrypt_private_key
)
from micropki.templates import CertificateTemplate, TemplateType, SANEntry, SANType


def generate_intermediate_csr(
        subject_components: dict,
        key_type: str,
        key_size: int,
        pathlen: int = 0,
        logger=None
) -> Tuple[Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], x509.CertificateSigningRequest]:
    """
    Generate a CSR for an Intermediate CA.

    Returns:
        Tuple of (private_key, csr)
    """
    if logger:
        logger.info(f"Generating Intermediate CA CSR with subject: {subject_components}")

    # Generate key pair
    if key_type == 'rsa':
        private_key = generate_rsa_key(key_size)
    else:
        private_key = generate_ecc_key(key_size)

    # Create subject name
    subject = create_dn_from_components(subject_components)

    # Build CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # Add Basic Constraints extension (optional in CSR, recommended)
    csr_builder = csr_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True
    )

    # Add Key Usage extension (optional in CSR)
    csr_builder = csr_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
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

    # Sign CSR
    if key_type == 'rsa':
        signature_hash = hashes.SHA256()
    else:
        signature_hash = hashes.SHA384()

    csr = csr_builder.sign(private_key, signature_hash, default_backend())

    if logger:
        logger.info(f"Intermediate CA CSR generated successfully")

    return private_key, csr


def sign_intermediate_csr(
        csr: x509.CertificateSigningRequest,
        root_cert: x509.Certificate,
        root_private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        validity_days: int,
        pathlen: int = 0,
        serial_number: Optional[int] = None,
        logger=None
) -> x509.Certificate:
    """
    Sign an Intermediate CA CSR with the Root CA private key.
    """
    if logger:
        logger.info("Signing Intermediate CA CSR with Root CA")

    # Generate serial number if not provided
    if serial_number is None:
        from micropki.crypto_utils import generate_serial_number
        serial_number = generate_serial_number()

    # Set validity period
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    # Compute SKI from CSR public key
    ski = compute_ski(csr.public_key())

    # Get Root CA SKI for AKI
    root_ski = root_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value.digest

    # Build certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(csr.subject)
    cert_builder = cert_builder.issuer_name(root_cert.subject)
    cert_builder = cert_builder.not_valid_before(not_before)
    cert_builder = cert_builder.not_valid_after(not_after)
    cert_builder = cert_builder.serial_number(serial_number)
    cert_builder = cert_builder.public_key(csr.public_key())

    # Add extensions
    # Basic Constraints: CA=TRUE, pathLenConstraint (critical)
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=pathlen),
        critical=True
    )

    # Key Usage: keyCertSign, cRLSign (critical)
    cert_builder = cert_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
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

    # Authority Key Identifier
    cert_builder = cert_builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=root_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    # Sign certificate
    if isinstance(root_private_key, rsa.RSAPrivateKey):
        signature_hash = hashes.SHA256()
    else:
        signature_hash = hashes.SHA384()

    certificate = cert_builder.sign(
        private_key=root_private_key,
        algorithm=signature_hash,
        backend=default_backend()
    )

    if logger:
        logger.info(f"Intermediate CA certificate signed successfully. Serial: {format(serial_number, 'x')}")

    return certificate


def parse_san_strings(san_strings: List[str]) -> List[SANEntry]:
    """
    Parse SAN strings of format "type:value".
    Example: "dns:example.com", "ip:192.168.1.1", "email:user@example.com"
    """
    entries = []

    for san_str in san_strings:
        if ':' not in san_str:
            raise ValueError(f"Invalid SAN format: {san_str}. Expected 'type:value'")

        type_str, value = san_str.split(':', 1)
        type_str = type_str.strip().lower()
        value = value.strip()

        if not value:
            raise ValueError(f"Empty value for SAN type: {type_str}")

        san_type = SANType.from_string(type_str)
        entries.append(SANEntry(san_type, value))

    return entries


def sign_external_csr(
        csr_path: Path,
        ca_cert: x509.Certificate,
        ca_private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        template: CertificateTemplate,
        validity_days: int,
        san_entries: List[SANEntry] = None,
        logger=None
) -> x509.Certificate:
    """
    Sign an external CSR to issue a certificate.
    """
    if logger:
        logger.info(f"Signing external CSR from: {csr_path}")

    # Load CSR
    with open(csr_path, 'rb') as f:
        csr_data = f.read()

    csr = x509.load_pem_x509_csr(csr_data, default_backend())

    # Verify CSR signature
    if not csr.is_signature_valid:
        raise ValueError("CSR signature verification failed")

    # Check if CSR requests CA=true (should be rejected for end-entity)
    try:
        basic_constraints = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        if basic_constraints.value.ca:
            if logger:
                logger.warning("CSR requests CA=true, overriding to CA=false for end-entity certificate")
    except x509.extensions.ExtensionNotFound:
        pass  # No Basic Constraints, which is fine

    # Generate serial number
    from micropki.crypto_utils import generate_serial_number
    serial_number = generate_serial_number()

    # Set validity period
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    # Compute SKI from CSR public key
    ski = compute_ski(csr.public_key())

    # Get CA SKI for AKI
    ca_ski = ca_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value.digest

    # Build certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(csr.subject)
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    cert_builder = cert_builder.not_valid_before(not_before)
    cert_builder = cert_builder.not_valid_after(not_after)
    cert_builder = cert_builder.serial_number(serial_number)
    cert_builder = cert_builder.public_key(csr.public_key())

    # Add template extensions
    for extension in template.build_extensions(san_entries or []):
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
    if isinstance(ca_private_key, rsa.RSAPrivateKey):
        signature_hash = hashes.SHA256()
    else:
        signature_hash = hashes.SHA384()

    certificate = cert_builder.sign(
        private_key=ca_private_key,
        algorithm=signature_hash,
        backend=default_backend()
    )

    if logger:
        logger.info(f"Certificate issued successfully. Serial: {format(serial_number, 'x')}")

    return certificate
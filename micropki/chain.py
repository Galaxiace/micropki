from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature


class ChainValidationError(Exception):
    """Custom exception for chain validation errors"""
    pass


def load_certificate(cert_path: Path) -> x509.Certificate:
    """Load a PEM certificate from file"""
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())


def load_certificates_from_paths(cert_paths: List[Path]) -> List[x509.Certificate]:
    """Load multiple certificates from paths"""
    return [load_certificate(path) for path in cert_paths]


def verify_signature(
        cert: x509.Certificate,
        issuer_cert: x509.Certificate
) -> bool:
    """
    Verify that cert is signed by issuer_cert.
    """
    try:
        issuer_public_key = issuer_cert.public_key()

        # Get the signature algorithm from the certificate
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # For RSA, use PKCS1v15 with the appropriate hash
            cert.signature_hash_algorithm.name
            hash_algo = cert.signature_hash_algorithm
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algo
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            # For ECC, use ECDSA
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            raise ChainValidationError(f"Unsupported public key type: {type(issuer_public_key)}")

        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise ChainValidationError(f"Signature verification failed: {e}")


def check_validity_period(cert: x509.Certificate, reference_time: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    Check if certificate is valid at the reference time.
    Returns (is_valid, message)
    """
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    if reference_time < cert.not_valid_before_utc:
        return False, f"Certificate not yet valid. Valid from: {cert.not_valid_before_utc}"

    if reference_time > cert.not_valid_after_utc:
        return False, f"Certificate expired. Valid until: {cert.not_valid_after_utc}"

    return True, "Certificate is within validity period"


def check_basic_constraints(cert: x509.Certificate, expected_ca: bool = None) -> Tuple[bool, str]:
    """
    Check Basic Constraints extension.
    """
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )

        is_ca = basic_constraints.value.ca

        if expected_ca is not None and is_ca != expected_ca:
            return False, f"Basic Constraints CA flag mismatch: expected {expected_ca}, got {is_ca}"

        if is_ca:
            pathlen = basic_constraints.value.path_length
            return True, f"CA certificate with path length: {pathlen}"
        else:
            return True, "End-entity certificate (CA=FALSE)"

    except x509.extensions.ExtensionNotFound:
        if expected_ca is True:
            return False, "Basic Constraints extension not found, but CA certificate expected"
        # For end-entity, missing Basic Constraints is allowed but we'll warn
        return True, "Warning: Basic Constraints extension not found (should be present for v3 certificates)"


def check_key_usage(cert: x509.Certificate, required_usages: List[str]) -> Tuple[bool, str]:
    """
    Check Key Usage extension for required usages.
    """
    try:
        key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )

        usage_map = {
            'digital_signature': key_usage.value.digital_signature,
            'content_commitment': key_usage.value.content_commitment,
            'key_encipherment': key_usage.value.key_encipherment,
            'data_encipherment': key_usage.value.data_encipherment,
            'key_agreement': key_usage.value.key_agreement,
            'key_cert_sign': key_usage.value.key_cert_sign,
            'crl_sign': key_usage.value.crl_sign,
            'encipher_only': key_usage.value.encipher_only,
            'decipher_only': key_usage.value.decipher_only,
        }

        missing = []
        for usage in required_usages:
            if usage not in usage_map:
                return False, f"Unknown key usage: {usage}"
            if not usage_map[usage]:
                missing.append(usage)

        if missing:
            return False, f"Missing required key usages: {', '.join(missing)}"

        return True, "Key Usage check passed"

    except x509.extensions.ExtensionNotFound:
        return False, "Key Usage extension not found (required for v3 certificates)"


def validate_chain(
        leaf_cert: x509.Certificate,
        intermediate_certs: List[x509.Certificate],
        root_cert: x509.Certificate,
        reference_time: Optional[datetime] = None
) -> List[str]:
    """
    Validate a full certificate chain:
    leaf -> intermediates... -> root

    Returns list of validation messages (empty if chain is valid).
    """
    messages = []

    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    # Build full chain
    chain = [leaf_cert] + intermediate_certs + [root_cert]

    # Check each certificate's validity period
    for i, cert in enumerate(chain[:-1]):  # Skip root for now
        valid, msg = check_validity_period(cert, reference_time)
        if not valid:
            messages.append(f"Certificate {i} (issuer: {cert.issuer.rfc4514_string()}): {msg}")

    # Check root validity
    valid, msg = check_validity_period(root_cert, reference_time)
    if not valid:
        messages.append(f"Root certificate: {msg}")

    # Check signatures up the chain
    for i in range(len(chain) - 1):
        cert = chain[i]
        issuer = chain[i + 1]

        # Verify signature
        if not verify_signature(cert, issuer):
            messages.append(
                f"Signature verification failed: "
                f"Certificate {i} not signed by its issuer"
            )

        # Check Basic Constraints for issuers
        if i < len(chain) - 2:  # All except leaf and root? Actually all issuers should be CA
            valid, msg = check_basic_constraints(issuer, expected_ca=True)
            if not valid:
                messages.append(f"Issuer certificate {i + 1} (CA): {msg}")

    # Check leaf certificate Basic Constraints (should be CA=FALSE)
    valid, msg = check_basic_constraints(leaf_cert, expected_ca=False)
    if not valid:
        messages.append(f"Leaf certificate: {msg}")

    # Check root certificate Basic Constraints (should be CA=TRUE)
    valid, msg = check_basic_constraints(root_cert, expected_ca=True)
    if not valid:
        messages.append(f"Root certificate: {msg}")

    return messages


def verify_chain_with_openssl(
        leaf_path: Path,
        intermediate_paths: List[Path],
        root_path: Path,
        logger=None
) -> Tuple[bool, str]:
    """
    Verify chain using OpenSSL command-line tool.
    Returns (success, output)
    """
    import subprocess
    import tempfile

    # Create a temporary file with the full chain
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as chain_file:
        # Write leaf
        with open(leaf_path, 'r') as f:
            chain_file.write(f.read())

        # Write intermediates
        for int_path in intermediate_paths:
            with open(int_path, 'r') as f:
                chain_file.write(f.read())

        chain_file_path = chain_file.name

    try:
        # Run openssl verify
        cmd = [
            'openssl', 'verify',
            '-CAfile', str(root_path),
            '-untrusted', str(chain_file_path),
            str(leaf_path)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr

    finally:
        # Clean up temp file
        Path(chain_file_path).unlink(missing_ok=True)


def print_chain_info(
        leaf_cert: x509.Certificate,
        intermediate_certs: List[x509.Certificate],
        root_cert: x509.Certificate,
        logger
):
    """Print information about the certificate chain"""

    logger.info("=== Certificate Chain Information ===")

    # Leaf certificate
    logger.info(f"Leaf Certificate:")
    logger.info(f"  Subject: {leaf_cert.subject.rfc4514_string()}")
    logger.info(f"  Issuer: {leaf_cert.issuer.rfc4514_string()}")
    logger.info(f"  Serial: {format(leaf_cert.serial_number, 'x')}")
    logger.info(f"  Validity: {leaf_cert.not_valid_before_utc} to {leaf_cert.not_valid_after_utc}")

    # Intermediates
    for i, cert in enumerate(intermediate_certs):
        logger.info(f"Intermediate {i + 1}:")
        logger.info(f"  Subject: {cert.subject.rfc4514_string()}")
        logger.info(f"  Issuer: {cert.issuer.rfc4514_string()}")
        logger.info(f"  Serial: {format(cert.serial_number, 'x')}")

    # Root
    logger.info(f"Root Certificate:")
    logger.info(f"  Subject: {root_cert.subject.rfc4514_string()}")
    logger.info(f"  Serial: {format(root_cert.serial_number, 'x')}")
    logger.info("=" * 40)
#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import os
from typing import List, Optional

from micropki.ca import initialize_root_ca, issue_intermediate_ca, issue_end_entity_certificate, \
    validate_certificate_chain
from micropki.logger import setup_logger
from micropki import __version__


def parse_dn(dn_string: str) -> dict:
    """Parse Distinguished Name string"""
    components = {}
    dn_string = dn_string.strip()

    if not dn_string:
        return components

    if dn_string.startswith('/'):
        # Format: /CN=name/O=org/C=country
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                components[key.strip()] = value.strip()
    else:
        # Format: CN=name,O=org,C=country
        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                components[key.strip()] = value.strip()

    return components


def validate_ca_init_args(args):
    """Validate arguments for ca init command"""
    errors = []

    if not args.subject:
        errors.append("--subject must be provided and non-empty")

    if args.key_type not in ['rsa', 'ecc']:
        errors.append(f"--key-type must be 'rsa' or 'ecc'")

    if args.key_type == 'rsa' and args.key_size != 4096:
        errors.append(f"RSA key size must be 4096 bits")
    elif args.key_type == 'ecc' and args.key_size != 384:
        errors.append(f"ECC key size must be 384 bits")

    if args.passphrase_file:
        passphrase_path = Path(args.passphrase_file)
        if not passphrase_path.exists():
            errors.append(f"Passphrase file does not exist: {args.passphrase_file}")
        elif not os.access(passphrase_path, os.R_OK):
            errors.append(f"Passphrase file is not readable: {args.passphrase_file}")

    if args.validity_days <= 0:
        errors.append(f"Validity days must be positive")

    out_dir = Path(args.out_dir)
    if out_dir.exists() and not os.access(out_dir, os.W_OK):
        errors.append(f"Output directory is not writable: {args.out_dir}")

    return errors


def validate_issue_intermediate_args(args):
    """Validate arguments for ca issue-intermediate command"""
    errors = []

    # Check required files
    required_files = [
        ('--root-cert', args.root_cert),
        ('--root-key', args.root_key),
        ('--root-pass-file', args.root_pass_file),
        ('--passphrase-file', args.passphrase_file)
    ]

    for name, path in required_files:
        if not path:
            errors.append(f"{name} is required")
        else:
            file_path = Path(path)
            if not file_path.exists():
                errors.append(f"{name} file does not exist: {path}")
            elif not os.access(file_path, os.R_OK):
                errors.append(f"{name} file is not readable: {path}")

    # Validate subject
    if not args.subject:
        errors.append("--subject must be provided and non-empty")

    # Validate key type and size
    if args.key_type not in ['rsa', 'ecc']:
        errors.append(f"--key-type must be 'rsa' or 'ecc'")

    if args.key_type == 'rsa' and args.key_size != 4096:
        errors.append(f"RSA key size must be 4096 bits")
    elif args.key_type == 'ecc' and args.key_size != 384:
        errors.append(f"ECC key size must be 384 bits")

    # Validate pathlen
    if args.pathlen < 0:
        errors.append(f"--pathlen must be non-negative")

    # Validate validity days
    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive")

    # Check output directory writability
    out_dir = Path(args.out_dir)
    if out_dir.exists() and not os.access(out_dir, os.W_OK):
        errors.append(f"Output directory is not writable: {args.out_dir}")

    return errors


def validate_issue_cert_args(args):
    """Validate arguments for ca issue-cert command"""
    errors = []

    # Check required files
    required_files = [
        ('--ca-cert', args.ca_cert),
        ('--ca-key', args.ca_key),
        ('--ca-pass-file', args.ca_pass_file)
    ]

    for name, path in required_files:
        if not path:
            errors.append(f"{name} is required")
        else:
            file_path = Path(path)
            if not file_path.exists():
                errors.append(f"{name} file does not exist: {path}")
            elif not os.access(file_path, os.R_OK):
                errors.append(f"{name} file is not readable: {path}")

    # Validate template
    valid_templates = ['server', 'client', 'code_signing']
    if not args.template:
        errors.append("--template is required")
    elif args.template not in valid_templates:
        errors.append(f"--template must be one of: {', '.join(valid_templates)}")

    # Validate subject
    if not args.subject:
        errors.append("--subject must be provided and non-empty")

    # Validate SAN entries if provided
    if args.san:
        for san in args.san:
            if ':' not in san:
                errors.append(f"Invalid SAN format: {san}. Expected 'type:value'")
            else:
                san_type = san.split(':', 1)[0].lower()
                valid_types = ['dns', 'ip', 'email', 'uri']
                if san_type not in valid_types:
                    errors.append(f"Invalid SAN type: {san_type}. Must be one of: {', '.join(valid_types)}")

    # Validate CSR if provided
    if args.csr:
        csr_path = Path(args.csr)
        if not csr_path.exists():
            errors.append(f"CSR file does not exist: {args.csr}")
        elif not csr_path.is_file():
            errors.append(f"CSR path is not a file: {args.csr}")

    # Validate validity days
    if args.validity_days <= 0:
        errors.append(f"--validity-days must be positive")

    # Check output directory writability
    out_dir = Path(args.out_dir)
    if out_dir.exists() and not os.access(out_dir, os.W_OK):
        errors.append(f"Output directory is not writable: {args.out_dir}")
    elif not out_dir.exists():
        # Try to create parent directory
        try:
            out_dir.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create output directory: {e}")

    return errors


def validate_chain_verify_args(args):
    """Validate arguments for ca verify-chain command"""
    errors = []

    if not args.leaf:
        errors.append("--leaf is required")
    else:
        leaf_path = Path(args.leaf)
        if not leaf_path.exists():
            errors.append(f"Leaf certificate not found: {args.leaf}")

    if not args.root:
        errors.append("--root is required")
    else:
        root_path = Path(args.root)
        if not root_path.exists():
            errors.append(f"Root certificate not found: {args.root}")

    # Intermediates are optional, but if provided, check they exist
    if args.intermediate:
        for int_path in args.intermediate:
            path = Path(int_path)
            if not path.exists():
                errors.append(f"Intermediate certificate not found: {int_path}")

    return errors


def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="MicroPKI - Minimal Public Key Infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize Root CA
  micropki ca init --subject "/CN=My Root CA" --passphrase-file ./secrets/root.pass

  # Issue Intermediate CA
  micropki ca issue-intermediate \\
    --root-cert ./pki/certs/ca.cert.pem \\
    --root-key ./pki/private/ca.key.pem \\
    --root-pass-file ./secrets/root.pass \\
    --subject "CN=Intermediate CA,O=MicroPKI" \\
    --passphrase-file ./secrets/intermediate.pass

  # Issue Server Certificate
  micropki ca issue-cert \\
    --ca-cert ./pki/certs/intermediate.cert.pem \\
    --ca-key ./pki/private/intermediate.key.pem \\
    --ca-pass-file ./secrets/intermediate.pass \\
    --template server \\
    --subject "CN=example.com" \\
    --san dns:example.com --san dns:www.example.com

  # Verify Certificate Chain
  micropki ca verify-chain \\
    --leaf ./pki/certs/example.com.cert.pem \\
    --intermediate ./pki/certs/intermediate.cert.pem \\
    --root ./pki/certs/ca.cert.pem
        """
    )

    parser.add_argument('--version', action='version', version=f'MicroPKI {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # CA command group
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA commands')

    # ========== ca init command ==========
    init_parser = ca_subparsers.add_parser('init', help='Initialize a new Root CA')
    init_parser.add_argument('--subject', required=True, help='Distinguished Name (e.g., "/CN=My CA/O=Org/C=RU")')
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type (default: rsa)')
    init_parser.add_argument('--key-size', type=int, default=4096, help='Key size in bits (rsa:4096, ecc:384)')
    init_parser.add_argument('--passphrase-file', required=True,
                             help='File containing passphrase for CA key encryption')
    init_parser.add_argument('--out-dir', default='./pki', help='Output directory (default: ./pki)')
    init_parser.add_argument('--validity-days', type=int, default=3650, help='Validity period in days (default: 3650)')
    init_parser.add_argument('--log-file', help='Optional path to log file')

    # ========== ca issue-intermediate command ==========
    int_parser = ca_subparsers.add_parser('issue-intermediate', help='Issue an Intermediate CA certificate')
    int_parser.add_argument('--root-cert', required=True, help='Path to Root CA certificate (PEM)')
    int_parser.add_argument('--root-key', required=True, help='Path to Root CA encrypted private key (PEM)')
    int_parser.add_argument('--root-pass-file', required=True, help='File containing passphrase for Root CA key')
    int_parser.add_argument('--subject', required=True, help='Distinguished Name for Intermediate CA')
    int_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type (default: rsa)')
    int_parser.add_argument('--key-size', type=int, default=4096, help='Key size (rsa:4096, ecc:384)')
    int_parser.add_argument('--passphrase-file', required=True,
                            help='File containing passphrase for Intermediate CA key')
    int_parser.add_argument('--out-dir', default='./pki', help='Output directory (default: ./pki)')
    int_parser.add_argument('--validity-days', type=int, default=1825,
                            help='Validity period in days (default: 1825 ≈ 5 years)')
    int_parser.add_argument('--pathlen', type=int, default=0, help='Path length constraint (default: 0)')
    int_parser.add_argument('--log-file', help='Optional path to log file')

    # ========== ca issue-cert command ==========
    cert_parser = ca_subparsers.add_parser('issue-cert', help='Issue an end-entity certificate')
    cert_parser.add_argument('--ca-cert', required=True, help='Path to Intermediate CA certificate (PEM)')
    cert_parser.add_argument('--ca-key', required=True, help='Path to Intermediate CA encrypted private key (PEM)')
    cert_parser.add_argument('--ca-pass-file', required=True, help='File containing passphrase for Intermediate CA key')
    cert_parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'],
                             help='Certificate template')
    cert_parser.add_argument('--subject', required=True, help='Distinguished Name for the certificate')
    cert_parser.add_argument('--san', action='append', help='Subject Alternative Name (e.g., dns:example.com)')
    cert_parser.add_argument('--out-dir', default='./pki/certs', help='Output directory (default: ./pki/certs)')
    cert_parser.add_argument('--validity-days', type=int, default=365, help='Validity period in days (default: 365)')
    cert_parser.add_argument('--csr', help='Optional: sign an external CSR instead of generating new key')
    cert_parser.add_argument('--log-file', help='Optional path to log file')

    # ========== ca verify command (existing) ==========
    verify_parser = ca_subparsers.add_parser('verify', help='Verify a single certificate')
    verify_parser.add_argument('--cert', required=True, help='Path to certificate file')
    verify_parser.add_argument('--log-file', help='Optional path to log file')

    # ========== ca verify-chain command (new) ==========
    chain_parser = ca_subparsers.add_parser('verify-chain', help='Verify a full certificate chain')
    chain_parser.add_argument('--leaf', required=True, help='Path to leaf certificate (PEM)')
    chain_parser.add_argument('--intermediate', action='append', help='Path to intermediate certificate(s) (PEM)')
    chain_parser.add_argument('--root', required=True, help='Path to root certificate (PEM)')
    chain_parser.add_argument('--log-file', help='Optional path to log file')

    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'ca':
        if not args.ca_command:
            parser.print_help()
            return 1

        # ========== CA INIT ==========
        if args.ca_command == 'init':
            errors = validate_ca_init_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1

            logger = setup_logger(args.log_file)

            try:
                # Read passphrase
                with open(args.passphrase_file, 'rb') as f:
                    passphrase = f.read().strip()

                # Parse DN
                dn_components = parse_dn(args.subject)
                if not dn_components:
                    logger.error("Failed to parse Distinguished Name")
                    return 1

                # Initialize Root CA
                success = initialize_root_ca(
                    subject_components=dn_components,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=passphrase,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    logger=logger
                )

                return 0 if success else 1

            except Exception as e:
                logger.error(f"Error: {e}")
                return 1

        # ========== CA ISSUE-INTERMEDIATE ==========
        elif args.ca_command == 'issue-intermediate':
            errors = validate_issue_intermediate_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1

            logger = setup_logger(args.log_file)

            try:
                # Read passphrases
                with open(args.root_pass_file, 'rb') as f:
                    root_passphrase = f.read().strip()

                with open(args.passphrase_file, 'rb') as f:
                    intermediate_passphrase = f.read().strip()

                # Parse DN
                dn_components = parse_dn(args.subject)
                if not dn_components:
                    logger.error("Failed to parse Distinguished Name")
                    return 1

                # Issue Intermediate CA
                success = issue_intermediate_ca(
                    root_cert_path=Path(args.root_cert),
                    root_key_path=Path(args.root_key),
                    root_passphrase=root_passphrase,
                    subject_components=dn_components,
                    key_type=args.key_type,
                    key_size=args.key_size,
                    passphrase=intermediate_passphrase,
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    pathlen=args.pathlen,
                    logger=logger
                )

                if success:
                    logger.info("✓ Intermediate CA issued successfully")

                    # Show next steps
                    logger.info("\nNext steps:")
                    logger.info("1. To issue a server certificate:")
                    logger.info(f"   micropki ca issue-cert \\")
                    logger.info(f"     --ca-cert {args.out_dir}/certs/intermediate.cert.pem \\")
                    logger.info(f"     --ca-key {args.out_dir}/private/intermediate.key.pem \\")
                    logger.info(f"     --ca-pass-file {args.passphrase_file} \\")
                    logger.info(f"     --template server \\")
                    logger.info(f"     --subject \"CN=example.com\" \\")
                    logger.info(f"     --san dns:example.com")

                    return 0
                else:
                    return 1

            except Exception as e:
                logger.error(f"Error: {e}")
                return 1

        # ========== CA ISSUE-CERT ==========
        elif args.ca_command == 'issue-cert':
            errors = validate_issue_cert_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1

            logger = setup_logger(args.log_file)

            try:
                # Read CA passphrase
                with open(args.ca_pass_file, 'rb') as f:
                    ca_passphrase = f.read().strip()

                # Parse DN
                dn_components = parse_dn(args.subject)
                if not dn_components:
                    logger.error("Failed to parse Distinguished Name")
                    return 1

                # Parse CSR path if provided
                csr_path = Path(args.csr) if args.csr else None

                # Issue certificate
                success = issue_end_entity_certificate(
                    ca_cert_path=Path(args.ca_cert),
                    ca_key_path=Path(args.ca_key),
                    ca_passphrase=ca_passphrase,
                    template_name=args.template,
                    subject_components=dn_components,
                    san_strings=args.san or [],
                    out_dir=args.out_dir,
                    validity_days=args.validity_days,
                    csr_path=csr_path,
                    logger=logger
                )

                return 0 if success else 1

            except Exception as e:
                logger.error(f"Error: {e}")
                return 1

        # ========== CA VERIFY (single certificate) ==========
        elif args.ca_command == 'verify':
            logger = setup_logger(args.log_file)

            try:
                from micropki.verification import verify_certificate

                cert_path = Path(args.cert)
                if not cert_path.exists():
                    logger.error(f"Certificate file not found: {args.cert}")
                    return 1

                logger.info(f"Verifying certificate: {cert_path}")
                success = verify_certificate(str(cert_path), logger)

                if success:
                    logger.info("✓ Certificate verification PASSED")
                    return 0
                else:
                    logger.error("✗ Certificate verification FAILED")
                    return 1

            except ImportError as e:
                logger.error(f"Failed to import verification module: {e}")
                return 1
            except Exception as e:
                logger.error(f"Verification failed: {e}")
                return 1

        # ========== CA VERIFY-CHAIN ==========
        elif args.ca_command == 'verify-chain':
            errors = validate_chain_verify_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1

            logger = setup_logger(args.log_file)

            try:
                # Prepare certificate paths
                leaf_path = Path(args.leaf)
                root_path = Path(args.root)
                intermediate_paths = [Path(p) for p in (args.intermediate or [])]

                # Validate chain
                success = validate_certificate_chain(
                    leaf_path=leaf_path,
                    intermediate_paths=intermediate_paths,
                    root_path=root_path,
                    logger=logger
                )

                if success:
                    logger.info("✓ Certificate chain validation PASSED")
                    return 0
                else:
                    logger.error("✗ Certificate chain validation FAILED")
                    return 1

            except Exception as e:
                logger.error(f"Chain validation failed: {e}")
                return 1

        else:
            print(f"Unknown ca command: {args.ca_command}", file=sys.stderr)
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
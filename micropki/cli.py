#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import os

from micropki.ca import initialize_root_ca
from micropki.logger import setup_logger
from micropki import __version__


def parse_dn(dn_string: str) -> dict:
    """Parse Distinguished Name string"""
    components = {}
    dn_string = dn_string.strip()

    if not dn_string:
        return components

    if dn_string.startswith('/'):
        parts = dn_string[1:].split('/')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                components[key.strip()] = value.strip()
    else:
        parts = dn_string.split(',')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                components[key.strip()] = value.strip()

    return components


def validate_args(args):
    """Validate command line arguments"""
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
            errors.append(f"Passphrase file does not exist")
        elif not os.access(passphrase_path, os.R_OK):
            errors.append(f"Passphrase file is not readable")

    if args.validity_days <= 0:
        errors.append(f"Validity days must be positive")

    out_dir = Path(args.out_dir)
    if out_dir.exists() and not os.access(out_dir, os.W_OK):
        errors.append(f"Output directory is not writable")

    return errors


def create_parser():
    parser = argparse.ArgumentParser(description="MicroPKI - Minimal Public Key Infrastructure")
    parser.add_argument('--version', action='version', version=f'MicroPKI {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Commands')
    ca_parser = subparsers.add_parser('ca', help='CA operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA commands')

    # init command
    init_parser = ca_subparsers.add_parser('init', help='Initialize a new Root CA')
    init_parser.add_argument('--subject', required=True, help='Distinguished Name')
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki')
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file')

    # verify command
    verify_parser = ca_subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument('--cert', required=True, help='Path to certificate file')
    verify_parser.add_argument('--log-file', help='Optional path to log file')

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'ca':
        if args.ca_command == 'init':
            errors = validate_args(args)
            if errors:
                for error in errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1

            logger = setup_logger(args.log_file)

            try:
                with open(args.passphrase_file, 'rb') as f:
                    passphrase = f.read().strip()

                dn_components = parse_dn(args.subject)
                if not dn_components:
                    logger.error("Failed to parse Distinguished Name")
                    return 1

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

        elif args.ca_command == 'verify':
            logger = setup_logger(args.log_file)

            try:
                # Import here to avoid circular imports
                from micropki.verification import verify_certificate

                cert_path = Path(args.cert)
                if not cert_path.exists():
                    logger.error(f"Certificate file not found: {args.cert}")
                    return 1

                if not cert_path.is_file():
                    logger.error(f"Not a file: {args.cert}")
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
                logger.error("Make sure micropki.verification.py exists")
                return 1
            except Exception as e:
                logger.error(f"Verification failed: {e}")
                return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
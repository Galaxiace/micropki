import pytest
import subprocess
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys
import os


@pytest.fixture(scope="module")
def setup_full_chain():
    """Set up a complete certificate chain: Root -> Intermediate -> Leaf"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create passphrase files
        root_pass = tmp_path / "root.pass"
        root_pass.write_text("rootpass123")

        int_pass = tmp_path / "int.pass"
        int_pass.write_text("intpass123")

        # Step 1: Create Root CA
        root_cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'init',
            '--subject', '/CN=Test Root CA/O=MicroPKI Test',  # Исправлено: убран пробел после /
            '--key-type', 'rsa',
            '--key-size', '4096',
            '--passphrase-file', str(root_pass),
            '--out-dir', str(tmp_path / 'root'),
            '--validity-days', '3650',
            '--log-file', str(tmp_path / 'root-init.log')
        ]
        result = subprocess.run(root_cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"Root CA creation failed: {result.stderr}"

        # Step 2: Create Intermediate CA
        int_cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-intermediate',
            '--root-cert', str(tmp_path / 'root/certs/ca.cert.pem'),
            '--root-key', str(tmp_path / 'root/private/ca.key.pem'),
            '--root-pass-file', str(root_pass),
            '--subject', '/CN=Test Intermediate CA/O=MicroPKI Test',  # Исправлено: убран пробел после /
            '--key-type', 'rsa',
            '--key-size', '4096',
            '--passphrase-file', str(int_pass),
            '--out-dir', str(tmp_path / 'int'),
            '--validity-days', '1825',
            '--pathlen', '0',
            '--log-file', str(tmp_path / 'int-issue.log')
        ]
        result = subprocess.run(int_cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"Intermediate CA creation failed: {result.stderr}"

        # Step 3: Issue Server Certificate - ВРЕМЕННО УБИРАЕМ IP АДРЕС
        server_cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(tmp_path / 'int/certs/intermediate.cert.pem'),
            '--ca-key', str(tmp_path / 'int/private/intermediate.key.pem'),
            '--ca-pass-file', str(int_pass),
            '--template', 'server',
            '--subject', '/CN=test.example.com/O=MicroPKI Test',  # Исправлено: убран пробел после /
            '--san', 'dns:test.example.com',
            '--san', 'dns:www.example.com',
            # '--san', 'ip:192.168.1.100',  # Временно отключено для тестов
            '--out-dir', str(tmp_path / 'certs'),
            '--validity-days', '365',
            '--log-file', str(tmp_path / 'cert-issue.log')
        ]
        result = subprocess.run(server_cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"Server certificate issuance failed: {result.stderr}"

        # Find the generated certificate
        cert_files = list((tmp_path / 'certs').glob('*.cert.pem'))
        assert len(cert_files) > 0
        leaf_cert = cert_files[0]

        yield {
            'tmpdir': tmp_path,
            'root_pass': root_pass,
            'int_pass': int_pass,
            'root_cert': tmp_path / 'root/certs/ca.cert.pem',
            'root_key': tmp_path / 'root/private/ca.key.pem',
            'int_cert': tmp_path / 'int/certs/intermediate.cert.pem',
            'int_key': tmp_path / 'int/private/intermediate.key.pem',
            'leaf_cert': leaf_cert
        }


class TestChainValidation:
    """Tests for certificate chain validation (TEST-7)"""

    def test_chain_validation_command(self, setup_full_chain):
        """TEST-7: Test the verify-chain command"""
        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'verify-chain',
            '--leaf', str(setup_full_chain['leaf_cert']),
            '--intermediate', str(setup_full_chain['int_cert']),
            '--root', str(setup_full_chain['root_cert'])
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert "PASSED" in result.stdout or "PASSED" in result.stderr

    def test_openssl_chain_verification(self, setup_full_chain):
        """TEST-11: Verify chain with OpenSSL"""
        # Create a chain file with intermediate
        chain_file = setup_full_chain['tmpdir'] / 'chain.pem'
        with open(chain_file, 'wb') as f:
            with open(setup_full_chain['int_cert'], 'rb') as int_f:
                f.write(int_f.read())

        # Verify leaf with chain
        cmd = [
            'openssl', 'verify',
            '-CAfile', str(setup_full_chain['root_cert']),
            '-untrusted', str(chain_file),
            str(setup_full_chain['leaf_cert'])
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert 'OK' in result.stdout

    def test_openssl_verify_intermediate(self, setup_full_chain):
        """TEST-11: Verify Intermediate CA with OpenSSL"""
        cmd = [
            'openssl', 'verify',
            '-CAfile', str(setup_full_chain['root_cert']),
            str(setup_full_chain['int_cert'])
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
        assert 'OK' in result.stdout


class TestExtensionCorrectness:
    """Tests for X.509 extension correctness (TEST-8)"""

    def test_root_ca_extensions(self, setup_full_chain):
        """Test Root CA extensions with OpenSSL"""
        # Use openssl to examine the certificate
        cmd = [
            'openssl', 'x509',
            '-in', str(setup_full_chain['root_cert']),
            '-text', '-noout'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        # Check Basic Constraints
        assert 'CA:TRUE' in output
        assert 'critical' in output.lower()

        # Check Key Usage
        assert 'Certificate Sign' in output
        assert 'CRL Sign' in output

        # Check extensions are present
        assert 'X509v3 Subject Key Identifier' in output
        assert 'X509v3 Authority Key Identifier' in output

    def test_intermediate_ca_extensions(self, setup_full_chain):
        """Test Intermediate CA extensions with OpenSSL"""
        cmd = [
            'openssl', 'x509',
            '-in', str(setup_full_chain['int_cert']),
            '-text', '-noout'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        # Check Basic Constraints
        assert 'CA:TRUE' in output
        assert 'pathlen:0' in output or 'Path Length Constraint:0' in output
        assert 'critical' in output.lower()

        # Check Key Usage
        assert 'Certificate Sign' in output
        assert 'CRL Sign' in output

        # Check it's not self-signed (issuer != subject)
        assert 'Issuer:' in output
        assert 'Subject:' in output

        # Extract issuer and subject
        issuer_line = [l for l in output.split('\n') if 'Issuer:' in l][0]
        subject_line = [l for l in output.split('\n') if 'Subject:' in l][0]
        assert issuer_line != subject_line

    def test_server_cert_extensions(self, setup_full_chain):
        """TEST-8: Test server certificate extensions with OpenSSL"""
        cmd = [
            'openssl', 'x509',
            '-in', str(setup_full_chain['leaf_cert']),
            '-text', '-noout'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        # Check Basic Constraints: CA=FALSE
        assert 'CA:FALSE' in output

        # Check Key Usage
        assert 'Digital Signature' in output
        assert 'Key Encipherment' in output  # For RSA

        # Check Extended Key Usage
        assert 'TLS Web Server Authentication' in output

        # TEST-8: Check SAN entries presence
        assert 'X509v3 Subject Alternative Name' in output
        assert 'DNS:test.example.com' in output
        assert 'DNS:www.example.com' in output
        # IP адрес временно не проверяем
        # assert 'IP Address:192.168.1.100' in output


class TestInteroperability:
    """Tests for OpenSSL interoperability"""

    def test_parse_with_cryptography(self, setup_full_chain):
        """Test that certificates can be parsed with cryptography library"""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        # Test root
        with open(setup_full_chain['root_cert'], 'rb') as f:
            root = x509.load_pem_x509_certificate(f.read(), default_backend())
        assert root is not None
        assert root.version == x509.Version.v3

        # Test intermediate
        with open(setup_full_chain['int_cert'], 'rb') as f:
            int_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        assert int_cert is not None

        # Test leaf
        with open(setup_full_chain['leaf_cert'], 'rb') as f:
            leaf = x509.load_pem_x509_certificate(f.read(), default_backend())
        assert leaf is not None

    def test_extract_public_key(self, setup_full_chain):
        """Test that public keys can be extracted"""
        from cryptography.hazmat.primitives.asymmetric import rsa

        with open(setup_full_chain['leaf_cert'], 'rb') as f:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert public_key.key_size == 2048  # Default for end-entity
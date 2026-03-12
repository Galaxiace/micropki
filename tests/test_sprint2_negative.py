import pytest
import subprocess
import tempfile
from pathlib import Path
import os


class TestNegativeScenarios:
    """Test negative scenarios (TEST-10)"""

    @pytest.fixture(scope="class")
    def setup_ca(self):
        """Set up Root CA and Intermediate CA for tests"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Create passphrase files
            root_pass = tmp_path / "root.pass"
            root_pass.write_text("rootpass123")

            int_pass = tmp_path / "int.pass"
            int_pass.write_text("intpass123")

            # Create Root CA
            root_cmd = [
                'python', '-m', 'micropki.cli', 'ca', 'init',
                '--subject', '/CN=Test Root CA',
                '--key-type', 'rsa',
                '--key-size', '4096',
                '--passphrase-file', str(root_pass),
                '--out-dir', str(tmp_path / 'root'),
                '--validity-days', '365'
            ]
            result = subprocess.run(root_cmd, capture_output=True, text=True)
            assert result.returncode == 0, f"Root CA creation failed: {result.stderr}"

            # Create Intermediate CA
            int_cmd = [
                'python', '-m', 'micropki.cli', 'ca', 'issue-intermediate',
                '--root-cert', str(tmp_path / 'root/certs/ca.cert.pem'),
                '--root-key', str(tmp_path / 'root/private/ca.key.pem'),
                '--root-pass-file', str(root_pass),
                '--subject', '/CN=Test Intermediate CA',
                '--key-type', 'rsa',
                '--key-size', '4096',
                '--passphrase-file', str(int_pass),
                '--out-dir', str(tmp_path / 'int'),
                '--validity-days', '365',
                '--pathlen', '0'
            ]
            result = subprocess.run(int_cmd, capture_output=True, text=True)
            assert result.returncode == 0, f"Intermediate CA creation failed: {result.stderr}"

            yield {
                'tmpdir': tmp_path,
                'root_pass': root_pass,
                'int_pass': int_pass,
                'root_dir': tmp_path / 'root',
                'int_dir': tmp_path / 'int'
            }

    def test_server_cert_without_san(self, setup_ca):
        """TEST-10: Attempt to issue server certificate without SAN (should fail)"""
        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(setup_ca['int_dir'] / 'certs/intermediate.cert.pem'),
            '--ca-key', str(setup_ca['int_dir'] / 'private/intermediate.key.pem'),
            '--ca-pass-file', str(setup_ca['int_pass']),
            '--template', 'server',
            '--subject', '/CN=test.example.com',
            # No --san provided
            '--out-dir', str(setup_ca['tmpdir'] / 'certs'),
            '--validity-days', '30'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0
        assert "requires at least one SAN" in result.stderr or "requires at least one SAN" in result.stdout

    def test_unsupported_san_type_for_template(self, setup_ca):
        """TEST-10: Attempt to use unsupported SAN type for template"""
        # Server template with email SAN (not allowed)
        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(setup_ca['int_dir'] / 'certs/intermediate.cert.pem'),
            '--ca-key', str(setup_ca['int_dir'] / 'private/intermediate.key.pem'),
            '--ca-pass-file', str(setup_ca['int_pass']),
            '--template', 'server',
            '--subject', '/CN=test.example.com',
            '--san', 'email:test@example.com',  # Email not allowed for server
            '--out-dir', str(setup_ca['tmpdir'] / 'certs'),
            '--validity-days', '30'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0
        assert "not allowed" in result.stderr or "not allowed" in result.stdout

    def test_incorrect_passphrase_for_ca_key(self, setup_ca):
        """TEST-10: Use incorrect passphrase for Intermediate CA key"""
        # Create wrong passphrase file
        wrong_pass = setup_ca['tmpdir'] / "wrong.pass"
        wrong_pass.write_text("wrongpassword")

        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(setup_ca['int_dir'] / 'certs/intermediate.cert.pem'),
            '--ca-key', str(setup_ca['int_dir'] / 'private/intermediate.key.pem'),
            '--ca-pass-file', str(wrong_pass),  # Wrong passphrase
            '--template', 'server',
            '--subject', '/CN=test.example.com',
            '--san', 'dns:test.example.com',
            '--out-dir', str(setup_ca['tmpdir'] / 'certs'),
            '--validity-days', '30'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0
        # Error could be about decryption or password
        assert any(msg in (result.stderr + result.stdout).lower()
                   for msg in ['password', 'decrypt', 'key'])

    def test_sign_csr_with_ca_true(self, setup_ca):
        """TEST-10: Sign CSR that requests CA=true (should be rejected or overridden)"""
        # First create a CSR with CA=true using openssl
        csr_dir = setup_ca['tmpdir'] / 'csrs'
        csr_dir.mkdir()

        # Generate a key
        key_path = csr_dir / 'test.key'
        subprocess.run([
            'openssl', 'genrsa', '-out', str(key_path), '2048'
        ], check=True)

        # Create CSR with CA=true extension
        csr_config = csr_dir / 'csr.conf'
        csr_config.write_text("""
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = test.example.com

[v3_req]
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyEncipherment
""")

        csr_path = csr_dir / 'test.csr'
        subprocess.run([
            'openssl', 'req', '-new',
            '-key', str(key_path),
            '-out', str(csr_path),
            '-config', str(csr_config)
        ], check=True)

        # Try to sign this CSR
        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(setup_ca['int_dir'] / 'certs/intermediate.cert.pem'),
            '--ca-key', str(setup_ca['int_dir'] / 'private/intermediate.key.pem'),
            '--ca-pass-file', str(setup_ca['int_pass']),
            '--template', 'server',
            '--subject', '/CN=test.example.com',  # Subject in command line
            '--san', 'dns:test.example.com',
            '--csr', str(csr_path),
            '--out-dir', str(setup_ca['tmpdir'] / 'certs'),
            '--validity-days', '30'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        # Should either fail or succeed but with CA=false
        if result.returncode == 0:
            # If it succeeded, we need to verify the issued certificate has CA=false
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_files = list((setup_ca['tmpdir'] / 'certs').glob('*.cert.pem'))
            assert len(cert_files) > 0

            with open(cert_files[0], 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            assert basic_constraints.value.ca is False  # Should be overridden
        else:
            # Or it could fail with an error message
            assert result.returncode != 0

    def test_invalid_san_format(self, setup_ca):
        """Test invalid SAN format"""
        cmd = [
            'python', '-m', 'micropki.cli', 'ca', 'issue-cert',
            '--ca-cert', str(setup_ca['int_dir'] / 'certs/intermediate.cert.pem'),
            '--ca-key', str(setup_ca['int_dir'] / 'private/intermediate.key.pem'),
            '--ca-pass-file', str(setup_ca['int_pass']),
            '--template', 'server',
            '--subject', '/CN=test.example.com',
            '--san', 'dnsexample.com',  # Missing colon
            '--out-dir', str(setup_ca['tmpdir'] / 'certs'),
            '--validity-days', '30'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode != 0
        assert "Invalid SAN format" in result.stderr or "Invalid SAN format" in result.stdout
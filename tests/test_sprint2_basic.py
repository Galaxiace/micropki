import pytest
from pathlib import Path
import tempfile
import ipaddress  # Добавлено!
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from micropki.templates import (
    TemplateType, SANType, SANEntry, CertificateTemplate, get_template
)
from micropki.csr import (
    generate_intermediate_csr, parse_san_strings, sign_intermediate_csr
)
from micropki.crypto_utils import (
    generate_rsa_key, generate_ecc_key, create_dn_from_components,
    generate_serial_number, compute_ski
)


class TestTemplates:
    """Tests for certificate templates"""

    def test_template_types(self):
        """Test template type enumeration"""
        assert TemplateType.SERVER.value == "server"
        assert TemplateType.CLIENT.value == "client"
        assert TemplateType.CODE_SIGNING.value == "code_signing"

    def test_get_template(self):
        """Test getting template by name"""
        server = get_template("server")
        assert server.template_type == TemplateType.SERVER

        client = get_template("client")
        assert client.template_type == TemplateType.CLIENT

        code = get_template("code_signing")
        assert code.template_type == TemplateType.CODE_SIGNING

        with pytest.raises(ValueError):
            get_template("invalid")

    def test_template_allowed_san_types(self):
        """Test allowed SAN types per template"""
        server = get_template("server")
        allowed = server.get_allowed_san_types()
        assert SANType.DNS in allowed
        assert SANType.IP in allowed
        assert SANType.EMAIL not in allowed

        client = get_template("client")
        allowed = client.get_allowed_san_types()
        assert SANType.DNS in allowed
        assert SANType.EMAIL in allowed
        assert SANType.URI in allowed
        assert SANType.IP not in allowed

        code = get_template("code_signing")
        allowed = code.get_allowed_san_types()
        assert SANType.DNS in allowed
        assert SANType.URI in allowed
        assert SANType.IP not in allowed
        assert SANType.EMAIL not in allowed

    def test_template_required_san_types(self):
        """Test required SAN types per template"""
        server = get_template("server")
        required = server.get_required_san_types()
        assert SANType.DNS in required  # Server requires at least one DNS

        client = get_template("client")
        assert len(client.get_required_san_types()) == 0  # No strict requirement

        code = get_template("code_signing")
        assert len(code.get_required_san_types()) == 0  # No requirement

    def test_san_validation_server(self):
        """Test SAN validation for server template"""
        template = get_template("server")

        # Valid server SANs
        entries = [
            SANEntry(SANType.DNS, "example.com"),
            SANEntry(SANType.IP, "192.168.1.1")
        ]
        errors = template.validate_san_entries(entries)
        assert len(errors) == 0

        # Missing DNS (should fail)
        entries = [SANEntry(SANType.IP, "192.168.1.1")]
        errors = template.validate_san_entries(entries)
        assert len(errors) > 0
        assert "Missing required SAN type" in errors[0]

        # Invalid type for server
        entries = [SANEntry(SANType.DNS, "example.com"), SANEntry(SANType.EMAIL, "test@example.com")]
        errors = template.validate_san_entries(entries)
        assert len(errors) > 0
        assert "not allowed" in errors[0]

    def test_san_validation_client(self):
        """Test SAN validation for client template"""
        template = get_template("client")

        # Valid client SANs
        entries = [
            SANEntry(SANType.DNS, "client.example.com"),
            SANEntry(SANType.EMAIL, "user@example.com")
        ]
        errors = template.validate_san_entries(entries)
        assert len(errors) == 0

        # IP should not be allowed for client
        entries = [SANEntry(SANType.IP, "192.168.1.1")]
        errors = template.validate_san_entries(entries)
        assert len(errors) > 0
        assert "not allowed" in errors[0]

    def test_san_validation_code_signing(self):
        """Test SAN validation for code signing template"""
        template = get_template("code_signing")

        # Valid code signing SANs (DNS and URI)
        entries = [
            SANEntry(SANType.DNS, "signer.example.com"),
            SANEntry(SANType.URI, "https://example.com/signer")
        ]
        errors = template.validate_san_entries(entries)
        assert len(errors) == 0

        # Email should not be allowed
        entries = [SANEntry(SANType.EMAIL, "signer@example.com")]
        errors = template.validate_san_entries(entries)
        assert len(errors) > 0
        assert "not allowed" in errors[0]

    def test_build_extensions_server(self):
        """Test building extensions for server template"""
        template = get_template("server")
        entries = [
            SANEntry(SANType.DNS, "example.com"),
            SANEntry(SANType.IP, "192.168.1.1")
        ]

        extensions = template.build_extensions(entries)

        # Should have Basic Constraints, Key Usage, Extended Key Usage, and SAN
        assert len(extensions) >= 4

        # Check EKU
        eku_ext = next(ext for ext in extensions
                       if ext.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku_ext.value

        # Check SAN
        san_ext = next(ext for ext in extensions
                       if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        assert len(san_ext.value) == 2


class TestSANParsing:
    """Tests for SAN string parsing"""

    def test_parse_valid_san(self):
        """Test parsing valid SAN strings"""
        entries = parse_san_strings([
            "dns:example.com",
            "ip:192.168.1.1",
            "email:user@example.com",
            "uri:https://example.com"
        ])

        assert len(entries) == 4
        assert entries[0].type == SANType.DNS
        assert entries[0].value == "example.com"
        assert entries[1].type == SANType.IP
        assert entries[1].value == "192.168.1.1"
        assert entries[2].type == SANType.EMAIL
        assert entries[2].value == "user@example.com"
        assert entries[3].type == SANType.URI
        assert entries[3].value == "https://example.com"

    def test_parse_invalid_san(self):
        """Test parsing invalid SAN strings"""
        # Missing colon
        with pytest.raises(ValueError, match="Invalid SAN format"):
            parse_san_strings(["dns.example.com"])

        # Empty value
        with pytest.raises(ValueError, match="Empty value"):
            parse_san_strings(["dns:"])

        # Invalid type
        with pytest.raises(ValueError, match="Unsupported SAN type"):
            parse_san_strings(["invalid:example.com"])

    def test_san_to_general_name(self):
        """Test conversion to cryptography GeneralName"""
        entries = [
            SANEntry(SANType.DNS, "example.com"),
            SANEntry(SANType.IP, "192.168.1.1"),
            SANEntry(SANType.EMAIL, "user@example.com"),
            SANEntry(SANType.URI, "https://example.com")
        ]

        for entry in entries:
            gn = entry.to_general_name()
            assert gn is not None
            # Для IP адреса value будет объектом, а не строкой
            if entry.type == SANType.IP:
                assert str(gn.value) == entry.value
            else:
                assert gn.value == entry.value


class TestCSRGeneration:
    """Tests for CSR generation"""

    def test_generate_intermediate_csr_rsa(self):
        """Test generating Intermediate CA CSR with RSA"""
        subject = {
            'CN': 'Test Intermediate CA',
            'O': 'MicroPKI Test'
        }

        private_key, csr = generate_intermediate_csr(
            subject_components=subject,
            key_type='rsa',
            key_size=4096,
            pathlen=0
        )

        # Check CSR
        assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == 'Test Intermediate CA'
        assert csr.is_signature_valid

        # Check extensions in CSR
        basic_constraints = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 0

        key_usage = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True

    def test_generate_intermediate_csr_ecc(self):
        """Test generating Intermediate CA CSR with ECC"""
        subject = {
            'CN': 'Test Intermediate CA ECC',
            'O': 'MicroPKI Test'
        }

        private_key, csr = generate_intermediate_csr(
            subject_components=subject,
            key_type='ecc',
            key_size=384,
            pathlen=1  # Test with pathlen=1
        )

        assert csr.is_signature_valid

        # Check path length
        basic_constraints = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.path_length == 1


class TestSignIntermediate:
    """Tests for signing Intermediate CA CSR"""

    @pytest.fixture
    def root_ca_setup(self):
        """Create a test Root CA"""
        # Generate Root CA key
        root_key = generate_rsa_key(4096)
        root_subject = create_dn_from_components({'CN': 'Test Root CA'})

        # Create self-signed Root CA certificate
        serial = generate_serial_number()
        ski = compute_ski(root_key.public_key())

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(root_subject)
        cert_builder = cert_builder.issuer_name(root_subject)
        cert_builder = cert_builder.public_key(root_key.public_key())
        cert_builder = cert_builder.serial_number(serial)
        # Исправлено: убрано _utc
        cert_builder = cert_builder.not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        cert_builder = cert_builder.not_valid_after(datetime(2034, 1, 1, tzinfo=timezone.utc))

        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        )

        root_cert = cert_builder.sign(root_key, hashes.SHA256(), default_backend())

        return root_key, root_cert

    def test_sign_intermediate_csr(self, root_ca_setup):
        """Test signing an Intermediate CA CSR"""
        root_key, root_cert = root_ca_setup

        # Generate Intermediate CSR
        subject = {'CN': 'Test Intermediate'}
        int_private, csr = generate_intermediate_csr(subject, 'rsa', 4096, pathlen=0)

        # Sign CSR
        signed_cert = sign_intermediate_csr(
            csr=csr,
            root_cert=root_cert,
            root_private_key=root_key,
            validity_days=365,
            pathlen=0
        )

        # Verify the signed certificate
        assert signed_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == 'Test Intermediate'
        assert signed_cert.issuer == root_cert.subject

        # Check extensions
        basic_constraints = signed_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 0
        assert basic_constraints.critical is True

        key_usage = signed_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        assert key_usage.critical is True

        # Check SKI and AKI
        ski = signed_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        aki = signed_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ski.value.digest is not None
        assert aki.value.key_identifier is not None
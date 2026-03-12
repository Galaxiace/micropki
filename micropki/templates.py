from enum import Enum
from typing import List, Optional, Set
from dataclasses import dataclass
import ipaddress
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes


class TemplateType(Enum):
    """Supported certificate template types"""
    SERVER = "server"
    CLIENT = "client"
    CODE_SIGNING = "code_signing"


class SANType(Enum):
    """Supported Subject Alternative Name types"""
    DNS = "dns"
    IP = "ip"
    EMAIL = "email"
    URI = "uri"

    @classmethod
    def from_string(cls, value: str):
        """Convert string to SANType"""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Unsupported SAN type: {value}. Supported: dns, ip, email, uri")


@dataclass
class SANEntry:
    """Subject Alternative Name entry"""
    type: SANType
    value: str

    def to_general_name(self):
        """Convert to cryptography GeneralName"""
        if self.type == SANType.DNS:
            return x509.DNSName(self.value)
        elif self.type == SANType.IP:
            # Преобразуем строку IP в объект ipaddress
            try:
                ip = ipaddress.ip_address(self.value)
                return x509.IPAddress(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address: {self.value}")
        elif self.type == SANType.EMAIL:
            return x509.RFC822Name(self.value)
        elif self.type == SANType.URI:
            return x509.UniformResourceIdentifier(self.value)
        else:
            raise ValueError(f"Unsupported SAN type: {self.type}")


class CertificateTemplate:
    """
    Certificate template defining required extensions and policies.
    """

    def __init__(self, template_type: TemplateType):
        self.template_type = template_type
        self._validate_config()

    def _validate_config(self):
        """Validate template configuration"""
        # Template-specific validation will be done when building
        pass

    def get_allowed_san_types(self) -> Set[SANType]:
        """Get allowed SAN types for this template"""
        if self.template_type == TemplateType.SERVER:
            return {SANType.DNS, SANType.IP}
        elif self.template_type == TemplateType.CLIENT:
            return {SANType.DNS, SANType.EMAIL, SANType.URI}
        elif self.template_type == TemplateType.CODE_SIGNING:
            return {SANType.DNS, SANType.URI}
        else:
            return set()

    def get_required_san_types(self) -> Set[SANType]:
        """Get required SAN types for this template"""
        if self.template_type == TemplateType.SERVER:
            return {SANType.DNS}  # At least one DNS name required
        elif self.template_type == TemplateType.CLIENT:
            return set()  # No strict requirement, but email recommended
        elif self.template_type == TemplateType.CODE_SIGNING:
            return set()  # SAN not required
        else:
            return set()

    def validate_san_entries(self, san_entries: List[SANEntry]) -> List[str]:
        """
        Validate SAN entries against template requirements.
        Returns list of error messages (empty if valid).
        """
        errors = []

        if not san_entries and self.get_required_san_types():
            required = ", ".join(t.value for t in self.get_required_san_types())
            errors.append(f"Template {self.template_type.value} requires at least one SAN of type: {required}")
            return errors

        # Check each entry
        allowed_types = self.get_allowed_san_types()
        for entry in san_entries:
            if entry.type not in allowed_types:
                errors.append(
                    f"SAN type '{entry.type.value}' not allowed for {self.template_type.value} template. "
                    f"Allowed: {', '.join(t.value for t in allowed_types)}"
                )

        # Check for required types
        required_types = self.get_required_san_types()
        if required_types:
            present_types = {entry.type for entry in san_entries}
            missing = required_types - present_types
            if missing:
                missing_str = ", ".join(t.value for t in missing)
                errors.append(f"Missing required SAN type(s): {missing_str}")

        return errors

    def build_extensions(self, san_entries: List[SANEntry], ca_private_key=None) -> List[x509.Extension]:
        """
        Build X.509 extensions for this template.
        """
        extensions = []

        # Basic Constraints: CA=FALSE (critical)
        extensions.append(
            x509.Extension(
                oid=x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=x509.BasicConstraints(ca=False, path_length=None)
            )
        )

        # Key Usage based on template
        key_usage = self._get_key_usage()
        extensions.append(
            x509.Extension(
                oid=x509.oid.ExtensionOID.KEY_USAGE,
                critical=True,
                value=key_usage
            )
        )

        # Extended Key Usage based on template
        eku = self._get_extended_key_usage()
        if eku:
            extensions.append(
                x509.Extension(
                    oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
                    critical=False,
                    value=eku
                )
            )

        # Subject Alternative Name (if provided)
        if san_entries:
            san = x509.SubjectAlternativeName([
                entry.to_general_name() for entry in san_entries
            ])
            extensions.append(
                x509.Extension(
                    oid=x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    critical=False,
                    value=san
                )
            )

        return extensions

    def _get_key_usage(self) -> x509.KeyUsage:
        """Get Key Usage extension for this template"""
        if self.template_type == TemplateType.SERVER:
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,  # For RSA
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        elif self.template_type == TemplateType.CLIENT:
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,  # For ECDH
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        elif self.template_type == TemplateType.CODE_SIGNING:
            return x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            )
        else:
            raise ValueError(f"Unknown template type: {self.template_type}")

    def _get_extended_key_usage(self) -> Optional[x509.ExtendedKeyUsage]:
        """Get Extended Key Usage for this template"""
        if self.template_type == TemplateType.SERVER:
            return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        elif self.template_type == TemplateType.CLIENT:
            return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        elif self.template_type == TemplateType.CODE_SIGNING:
            return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        else:
            return None


# Factory function to get template
def get_template(template_name: str) -> CertificateTemplate:
    """Get certificate template by name"""
    try:
        template_type = TemplateType(template_name.lower())
        return CertificateTemplate(template_type)
    except ValueError:
        raise ValueError(f"Unknown template: {template_name}. Supported: server, client, code_signing")
import secrets
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    if key_size != 4096:
        raise ValueError(f"RSA key size must be 4096 bits, got {key_size}")

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ecc_key(key_size: int = 384) -> ec.EllipticCurvePrivateKey:
    if key_size != 384:
        raise ValueError(f"ECC key size must be 384 bits, got {key_size}")

    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )


def generate_serial_number() -> int:
    """
    Generate a cryptographically secure random serial number.
    RFC 5280 requires positive integers, and cryptography library
    requires serial number to be <= 159 bits (20 bytes with MSB cleared).
    """
    # Генерируем 19 байт + 1 байт с гарантированно очищенным старшим битом
    # Это даст максимум 159 бит (20 байт, но без установленного старшего бита)

    # Генерируем 20 байт
    random_bytes = secrets.token_bytes(20)

    # Очищаем самый старший бит (чтобы число было < 2^159)
    # 0x7F = 01111111 в двоичной (очищает старший бит)
    random_bytes = bytearray(random_bytes)
    random_bytes[0] &= 0x7F  # Сбрасываем старший бит

    # Убеждаемся, что число не ноль
    if all(b == 0 for b in random_bytes):
        # Если все нули (маловероятно), устанавливаем младший бит
        random_bytes[-1] = 1

    serial = int.from_bytes(random_bytes, byteorder='big')

    # Дополнительная проверка
    assert serial.bit_length() <= 159, f"Serial number too large: {serial.bit_length()} bits"
    assert serial > 0, "Serial number must be positive"

    return serial


def compute_ski(public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]) -> bytes:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(public_bytes)
    return digest.finalize()


def create_dn_from_components(components: dict) -> x509.Name:
    oid_map = {
        'CN': NameOID.COMMON_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'C': NameOID.COUNTRY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'L': NameOID.LOCALITY_NAME,
        'emailAddress': NameOID.EMAIL_ADDRESS,
    }

    attributes = []
    for key, value in components.items():
        if key in oid_map:
            attributes.append(x509.NameAttribute(oid_map[key], value))

    if not attributes:
        raise ValueError("No valid DN components found")

    return x509.Name(attributes)


def encrypt_private_key(private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], passphrase: bytes) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings


def encrypt_notification_secret(value: str) -> bytes:
    if not value:
        raise ValueError("Cannot encrypt empty notification secret")

    kek = base64.urlsafe_b64decode(settings.VAULT_KEK)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
    return nonce + encrypted


def decrypt_notification_secret(encrypted_data: bytes) -> str:
    if not encrypted_data:
        return ""

    kek = base64.urlsafe_b64decode(settings.VAULT_KEK)
    aesgcm = AESGCM(kek)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

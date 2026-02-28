import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
import os

def encrypt_root_key(root_key: bytes) -> bytes:
    kek = base64.urlsafe_b64decode(settings.VAULT_KEK)
    aesgcm = AESGCM(kek)

    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, root_key, None)

    return nonce + encrypted


def decrypt_root_key(encrypted_data: bytes) -> bytes:
    kek = base64.urlsafe_b64decode(settings.VAULT_KEK)
    aesgcm = AESGCM(kek)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)

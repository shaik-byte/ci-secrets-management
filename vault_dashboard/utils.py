import base64
import hashlib
from cryptography.fernet import Fernet


def get_fernet_from_session(request):
    key_b64 = request.session.get("vault_key")

    if not key_b64:
        raise Exception("Vault is sealed")

    key = base64.b64decode(key_b64)

    # Backward compatibility:
    # - Older sessions used 32-byte root keys directly (first 32 bytes).
    # - Newer setups may use 16-byte root keys; derive a stable 32-byte key.
    if len(key) >= 32:
        fernet_material = key[:32]
    else:
        fernet_material = hashlib.sha256(key).digest()

    return Fernet(base64.urlsafe_b64encode(fernet_material))


def encrypt_value(request, value):
    f = get_fernet_from_session(request)
    return f.encrypt(value.encode())


def decrypt_value(request, encrypted_value):
    f = get_fernet_from_session(request)
    return f.decrypt(encrypted_value).decode()

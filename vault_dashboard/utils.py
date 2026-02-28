import base64
from cryptography.fernet import Fernet


def get_fernet_from_session(request):
    key_b64 = request.session.get("vault_key")

    if not key_b64:
        raise Exception("Vault is sealed")

    key = base64.b64decode(key_b64)
    return Fernet(base64.urlsafe_b64encode(key[:32]))


def encrypt_value(request, value):
    f = get_fernet_from_session(request)
    return f.encrypt(value.encode())


def decrypt_value(request, encrypted_value):
    f = get_fernet_from_session(request)
    return f.decrypt(encrypted_value).decode()
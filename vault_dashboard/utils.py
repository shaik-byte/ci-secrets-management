import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_materials(root_key: bytes) -> list[bytes]:
    materials = []

    if len(root_key) >= 32:
        materials.append(root_key[:32])
    else:
        materials.append(hashlib.sha256(root_key).digest())
        materials.append((root_key + (b"\x00" * 32))[:32])

    # Keep unique order
    unique = []
    seen = set()
    for item in materials:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def get_fernet_from_session(request):
    key_b64 = request.session.get("vault_key")

    if not key_b64:
        raise Exception("Vault is sealed")

    key = base64.b64decode(key_b64)
    fernet_material = _derive_fernet_materials(key)[0]
    return Fernet(base64.urlsafe_b64encode(fernet_material))


def encrypt_value(request, value):
    f = get_fernet_from_session(request)
    return f.encrypt(value.encode())


def decrypt_value(request, encrypted_value):
    key_b64 = request.session.get("vault_key")
    if not key_b64:
        raise Exception("Vault is sealed")

    key = base64.b64decode(key_b64)
    materials = _derive_fernet_materials(key)

    # Also attempt with persisted root key in case session key is stale.
    try:
        from vault.models import VaultConfig
        from vault.crypto_utils import decrypt_root_key

        vault = VaultConfig.objects.first()
        if vault:
            materials.extend(_derive_fernet_materials(decrypt_root_key(vault.encrypted_root_key)))
    except Exception:
        pass

    tried = set()
    for material in materials:
        if material in tried:
            continue
        tried.add(material)
        f = Fernet(base64.urlsafe_b64encode(material))
        try:
            return f.decrypt(encrypted_value).decode()
        except InvalidToken:
            continue

    raise InvalidToken

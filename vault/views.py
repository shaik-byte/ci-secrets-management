import base64
import hmac
import json
import logging
import os
import hashlib
import secrets

from Crypto.Protocol.SecretSharing import Shamir
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache
from django.db import connections
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auditlogs.models import AuditLog

from .crypto_utils import decrypt_root_key, encrypt_root_key
from .models import VaultConfig
from .security import get_client_ip, get_location_from_ip

logger = logging.getLogger(__name__)


AUTH_METHOD_USERNAME_PASSWORD = "username_password"
AUTH_METHOD_ROOT_TOKEN = "root_token"
AUTH_CHANNEL_WEB = "WEB"
AUTH_CHANNEL_CLI = "CLI"
AUTH_CHANNEL_CLI_VIA_WEB = "CLI_VIA_WEB"
ROOT_SESSION_FLAG = "vault_root_authenticated"


def _system_user():
    user, _ = User.objects.get_or_create(
        username="__vault_system__",
        defaults={"is_active": False, "email": "vault-system@localhost"},
    )
    return user


def _record_vault_event(request, action, entity, details, user=None):
    AuditLog.objects.create(
        user=user or _system_user(),
        action=action,
        entity=entity,
        details=details,
        ip_address=get_client_ip(request),
    )


def _base64url_uint(value: int) -> str:
    byte_length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwks_public_key_path() -> str:
    return getattr(settings, "JWKS_PUBLIC_KEY_PATH", os.path.join(settings.BASE_DIR, "public_key.pem"))


def _rsa_public_key_to_jwk(public_key: rsa.RSAPublicKey) -> dict:
    numbers = public_key.public_numbers()
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = base64.urlsafe_b64encode(hashlib.sha256(der_bytes).digest()).decode().rstrip("=")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _base64url_uint(numbers.n),
        "e": _base64url_uint(numbers.e),
    }


def jwks_view(request):
    public_key_path = _jwks_public_key_path()
    try:
        with open(public_key_path, "rb") as pem_file:
            public_key = serialization.load_pem_public_key(pem_file.read())
    except FileNotFoundError:
        return JsonResponse({"error": f"Public key file not found: {public_key_path}"}, status=404)
    except ValueError:
        return JsonResponse({"error": "Invalid PEM public key format."}, status=400)

    if not isinstance(public_key, rsa.RSAPublicKey):
        return JsonResponse({"error": "Only RSA public keys are supported."}, status=400)

    return JsonResponse({"keys": [_rsa_public_key_to_jwk(public_key)]})


def _record_login_audit(request, user, auth_method, channel=AUTH_CHANNEL_WEB):
    login_method_label = "root_token" if auth_method == AUTH_METHOD_ROOT_TOKEN else "username_password"
    details = f"[{channel}] Authenticated via {login_method_label}"
    if channel == AUTH_CHANNEL_CLI_VIA_WEB:
        details += " (CLI used /login fallback)"
    AuditLog.objects.create(
        user=user,
        action="LOGIN",
        entity=channel,
        details=details,
        ip_address=get_client_ip(request),
    )


def _record_logout_audit(request, user, channel=AUTH_CHANNEL_WEB):
    AuditLog.objects.create(
        user=user,
        action="LOGOUT",
        entity=channel,
        details=f"[{channel}] Logged out",
        ip_address=get_client_ip(request),
    )


def _is_cli_web_fallback_request(request) -> bool:
    requested_client_channel = (request.POST.get("client_channel") or "").strip().lower()
    client_header = (request.headers.get("X-CIVault-Client") or "").strip().lower()
    if requested_client_channel == "cli" or client_header == "cli":
        return True

    user_agent = (request.headers.get("User-Agent") or "").lower()
    has_csrf_form_field = bool(request.POST.get("csrfmiddlewaretoken"))
    has_api_auth_payload = bool(request.POST.get("auth_method"))

    return (
        has_api_auth_payload
        and not has_csrf_form_field
        and user_agent.startswith("python-requests/")
    )


def format_share(index: int, share_bytes: bytes) -> str:
    return f"{index}-{share_bytes.hex()}"


def parse_share(share_value: str) -> tuple[int, bytes]:
    if "-" not in share_value:
        raise ValueError("Share must be in the format '<index>-<hex_share>'.")

    index_part, hex_part = share_value.split("-", 1)
    index = int(index_part)
    share_bytes = bytes.fromhex(hex_part.strip())

    if index < 1 or index > 255:
        raise ValueError("Share index is out of range.")

    return index, share_bytes


def _establish_authenticated_session(request, user, vault, root_key: bytes | None = None):
    login(request, user)
    request.session.cycle_key()

    if "vault_key" not in request.session:
        active_root_key = root_key if root_key is not None else decrypt_root_key(vault.encrypted_root_key)
        request.session["vault_key"] = base64.b64encode(active_root_key).decode()

    request.session["auth_user"] = {
        "id": user.id,
        "username": user.username,
        "is_superuser": user.is_superuser,
    }


def _authenticate_with_username_password(request, vault):
    username = (request.POST.get("username") or "").strip()
    password = request.POST.get("password")
    return _authenticate_username_password(request, vault, username, password)


def _authenticate_username_password(request, vault, username, password):
    username = (username or "").strip()

    user = authenticate(request, username=username, password=password)
    if not user:
        return None, "Invalid username or password."

    _establish_authenticated_session(request, user, vault)
    return user, None


def _authenticate_with_root_token(request, vault):
    token = (request.POST.get("root_token") or "").strip()
    return _authenticate_root_token(request, vault, token)


def _authenticate_root_token(request, vault, token):
    token = (token or "").strip()
    if not token:
        return None, "Root token is required."
    if not check_password(token, vault.root_token_hash):
        _record_vault_event(request, "LOGIN", "VaultRootLogin", "Root token login failed.")
        return None, "Invalid root token."

    if vault.is_sealed:
        return None, "Vault is sealed. Unseal before root login."

    root_user, _ = User.objects.get_or_create(
        username="vault-root",
        defaults={"email": "vault-root@localhost", "is_staff": True},
    )
    if not root_user.has_usable_password():
        root_user.set_unusable_password()
        root_user.save(update_fields=["password"])

    _establish_authenticated_session(request, root_user, vault)
    request.session[ROOT_SESSION_FLAG] = True
    _record_vault_event(request, "LOGIN", "VaultRootLogin", "Root token login success.", user=root_user)
    return root_user, None


@csrf_exempt
@require_POST
def cli_login(request):
    vault = VaultConfig.objects.first()
    if not vault:
        return JsonResponse({"ok": False, "error": "Vault is not initialized."}, status=503)
    if vault.is_sealed:
        return JsonResponse({"ok": False, "error": "Vault is sealed. Unseal before login."}, status=423)

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = request.POST

    auth_method = payload.get("auth_method", AUTH_METHOD_USERNAME_PASSWORD)
    if auth_method == AUTH_METHOD_ROOT_TOKEN:
        user, error = _authenticate_root_token(request, vault, payload.get("root_token"))
    elif auth_method == AUTH_METHOD_USERNAME_PASSWORD:
        user, error = _authenticate_username_password(
            request,
            vault,
            payload.get("username"),
            payload.get("password"),
        )
    else:
        return JsonResponse({"ok": False, "error": "Unsupported authentication method."}, status=400)

    if not user:
        return JsonResponse({"ok": False, "error": error or "Authentication failed."}, status=401)

    _record_login_audit(request, user, auth_method, channel="CLI")

    return JsonResponse(
        {
            "ok": True,
            "user": user.username,
            "is_superuser": user.is_superuser,
        }
    )


def home(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return redirect("initialize")

    if vault.is_sealed:
        return redirect("unseal")

    if not request.user.is_authenticated:
        return redirect("login")

    return redirect("vault_dashboard")


def initialize_vault(request):
    vault = VaultConfig.objects.first()

    if vault and vault.initialized:
        return redirect("unseal" if vault.is_sealed else "login")

    if request.method == "POST":
        try:
            total_shares = int(request.POST.get("total_shares", "5"))
            threshold = int(request.POST.get("threshold", "3"))
        except ValueError:
            return render(
                request,
                "initialize.html",
                {"error": "Total shares and threshold must be whole numbers."},
            )

        if total_shares < 2 or total_shares > 15:
            return render(
                request,
                "initialize.html",
                {"error": "Total shares must be between 2 and 15."},
            )

        if threshold < 2 or threshold > total_shares:
            return render(
                request,
                "initialize.html",
                {"error": "Threshold must be at least 2 and no greater than total shares."},
            )

        location = get_location_from_ip(get_client_ip(request)) or "LOCALHOST"
        root_key = os.urandom(16)
        root_token = secrets.token_urlsafe(32)
        encrypted_root_key = encrypt_root_key(root_key)

        VaultConfig.objects.create(
            encrypted_root_key=encrypted_root_key,
            allowed_location=location,
            initialized=True,
            sealed=True,
            total_shares=total_shares,
            threshold=threshold,
            root_token_hash=make_password(root_token),
            initialized_at=timezone.now(),
        )

        shares = [format_share(idx, share) for idx, share in Shamir.split(threshold, total_shares, root_key)]

        _record_vault_event(
            request,
            "CREATE",
            "VaultInitialization",
            f"Vault initialized with threshold {threshold}/{total_shares}.",
        )

        return render(
            request,
            "show_shares.html",
            {"shares": shares, "threshold": threshold, "total_shares": total_shares, "root_token": root_token},
        )

    return render(request, "initialize.html")


def unseal_vault(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return redirect("initialize")

    if request.method == "POST":
        share_value = (request.POST.get("share") or "").strip()
        submitted = request.session.get("submitted_unseal_shares", [])
        _record_vault_event(request, "UPDATE", "VaultUnseal", f"Unseal attempt submitted. Current count: {len(submitted)}.")

        try:
            share_index, share_bytes = parse_share(share_value)
        except Exception as exc:
            _record_vault_event(request, "UPDATE", "VaultUnseal", "Unseal failed: invalid share format.")
            return render(
                request,
                "unseal.html",
                {
                    "threshold": vault.threshold,
                    "submitted_count": len(submitted),
                    "error": str(exc),
                },
            )

        existing_indices = {item[0] for item in submitted}
        if share_index in existing_indices:
            return render(
                request,
                "unseal.html",
                {
                    "threshold": vault.threshold,
                    "submitted_count": len(submitted),
                    "error": f"Share index {share_index} has already been submitted.",
                },
            )

        submitted.append((share_index, share_bytes.hex()))
        request.session["submitted_unseal_shares"] = submitted

        logger.info(
            "Unseal share accepted",
            extra={"share_index": share_index, "submitted_count": len(submitted), "threshold": vault.threshold},
        )

        if len(submitted) >= vault.threshold:
            try:
                shares_for_combine = [(idx, bytes.fromhex(share_hex)) for idx, share_hex in submitted[: vault.threshold]]
                reconstructed_key = Shamir.combine(shares_for_combine)
                decrypted_root_key = decrypt_root_key(vault.encrypted_root_key)

                if not hmac.compare_digest(reconstructed_key, decrypted_root_key):
                    raise ValueError("Submitted shares are not valid for this vault.")

                request.session["vault_key"] = base64.b64encode(reconstructed_key).decode()
                vault.is_sealed = False
                vault.save(update_fields=["sealed"])
                cache.set("vault_hard_sealed", False, None)
                request.session["vault_hard_sealed"] = False
                request.session.pop("submitted_unseal_shares", None)

                _record_vault_event(request, "UPDATE", "VaultUnseal", "Vault unseal success.")
                return redirect("login")

            except Exception as exc:
                _record_vault_event(request, "UPDATE", "VaultUnseal", "Vault unseal failure.")
                request.session.pop("submitted_unseal_shares", None)
                return render(
                    request,
                    "unseal.html",
                    {
                        "threshold": vault.threshold,
                        "submitted_count": 0,
                        "error": str(exc),
                    },
                )

    return render(
        request,
        "unseal.html",
        {
            "threshold": vault.threshold,
            "submitted_count": len(request.session.get("submitted_unseal_shares", [])),
        },
    )


def login_view(request):
    vault = VaultConfig.objects.first()

    if not vault or vault.is_sealed:
        return render(request, "sealed.html")

    if request.method == "POST":
        user, error = _authenticate_with_username_password(request, vault)
        if user:
            channel = AUTH_CHANNEL_CLI_VIA_WEB if _is_cli_web_fallback_request(request) else AUTH_CHANNEL_WEB
            _record_login_audit(request, user, AUTH_METHOD_USERNAME_PASSWORD, channel=channel)
            return redirect("vault_dashboard")

        return render(request, "login.html", {"error": error or "Authentication failed."})

    return render(request, "login.html")


def root_token_login_view(request):
    vault = VaultConfig.objects.first()
    if not vault or vault.is_sealed:
        return render(request, "sealed.html")

    if request.method == "POST":
        user, error = _authenticate_with_root_token(request, vault)
        if user:
            return redirect("vault_dashboard")
        return render(request, "root_token_login.html", {"error": error or "Authentication failed."})
    return render(request, "root_token_login.html")


@login_required
@require_POST
def root_create_user(request):
    if not request.session.get(ROOT_SESSION_FLAG):
        return HttpResponseForbidden("Root token authentication is required.")

    username = (request.POST.get("username") or "").strip()
    password = request.POST.get("password") or ""
    policy_name = (request.POST.get("policy_name") or "").strip().lower()

    if not username or not password:
        return JsonResponse({"ok": False, "error": "username and password are required."}, status=400)

    if policy_name not in {"admin", "read-only", "secret-manager"}:
        return JsonResponse({"ok": False, "error": "Invalid policy_name."}, status=400)

    created_user = User.objects.create_user(username=username, password=password)

    try:
        from vault_dashboard.models import AccessPolicy

        policy_flags = {
            "admin": {"can_read": True, "can_write": True, "can_delete": True},
            "read-only": {"can_read": True, "can_write": False, "can_delete": False},
            "secret-manager": {"can_read": True, "can_write": True, "can_delete": False},
        }[policy_name]
        AccessPolicy.objects.create(user=created_user, **policy_flags)
    except Exception:
        pass

    _record_vault_event(
        request,
        "CREATE",
        "VaultUser",
        f"Root created user '{created_user.username}' with policy '{policy_name}'.",
        user=request.user,
    )
    return JsonResponse({"ok": True, "username": created_user.username, "policy_name": policy_name})


@login_required
@require_POST
def cli_logout(request):
    _record_logout_audit(request, request.user, channel="CLI")
    logout(request)
    request.session.flush()
    return JsonResponse({"ok": True})


@login_required
def dashboard(request):
    vault = VaultConfig.objects.first()

    if vault and vault.is_sealed:
        logout(request)
        return render(request, "sealed.html")

    return render(request, "dashboard.html")


def logout_view(request):
    # Session destruction point:
    # logout() removes authenticated user state; flush() destroys session data.
    if request.user.is_authenticated:
        _record_logout_audit(request, request.user, channel="WEB")
    logout(request)
    request.session.flush()
    return redirect("login")


@login_required
@require_POST
def seal_vault(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin users can seal the vault.")

    vault = VaultConfig.objects.first()

    if vault:
        vault.is_sealed = True
        vault.save(update_fields=["sealed"])

    cache.set("vault_hard_sealed", True, None)
    request.session["vault_hard_sealed"] = True

    connections.close_all()
    logout(request)
    return render(request, "sealed.html")

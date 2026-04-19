import base64
import hmac
import json
import logging
import os

from Crypto.Protocol.SecretSharing import Shamir
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import connections
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

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

    try:
        provided_root_key = base64.b64decode(token.encode())
    except Exception:
        return None, "Invalid root token format."

    expected_root_key = decrypt_root_key(vault.encrypted_root_key)
    if not hmac.compare_digest(provided_root_key, expected_root_key):
        return None, "Invalid root token."

    root_user = User.objects.filter(is_superuser=True).order_by("id").first()
    if not root_user:
        return None, "No admin/root account is available for root-token login."

    _establish_authenticated_session(request, root_user, vault, root_key=expected_root_key)
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

    if vault:
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
        encrypted_root_key = encrypt_root_key(root_key)

        VaultConfig.objects.create(
            encrypted_root_key=encrypted_root_key,
            allowed_location=location,
            is_sealed=True,
            total_shares=total_shares,
            threshold=threshold,
        )

        shares = [format_share(idx, share) for idx, share in Shamir.split(threshold, total_shares, root_key)]

        logger.info("Vault initialized with Shamir shares", extra={"total_shares": total_shares, "threshold": threshold})

        return render(
            request,
            "show_shares.html",
            {"shares": shares, "threshold": threshold, "total_shares": total_shares},
        )

    return render(request, "initialize.html")


def unseal_vault(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return redirect("initialize")

    if request.method == "POST":
        share_value = (request.POST.get("share") or "").strip()
        submitted = request.session.get("submitted_unseal_shares", [])

        try:
            share_index, share_bytes = parse_share(share_value)
        except Exception as exc:
            logger.warning("Invalid unseal share format", extra={"error": str(exc)})
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
                vault.save(update_fields=["is_sealed"])
                cache.set("vault_hard_sealed", False, None)
                request.session["vault_hard_sealed"] = False
                request.session.pop("submitted_unseal_shares", None)

                logger.info("Vault unsealed successfully")
                return redirect("login")

            except Exception as exc:
                logger.warning("Unseal failed after threshold shares", extra={"error": str(exc)})
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
        auth_method = request.POST.get("auth_method", AUTH_METHOD_USERNAME_PASSWORD)
        handlers = {
            AUTH_METHOD_USERNAME_PASSWORD: _authenticate_with_username_password,
            AUTH_METHOD_ROOT_TOKEN: _authenticate_with_root_token,
        }

        handler = handlers.get(auth_method)
        if not handler:
            return render(
                request,
                "login.html",
                {"error": "Unsupported authentication method.", "selected_auth_method": AUTH_METHOD_USERNAME_PASSWORD},
            )

        user, error = handler(request, vault)
        if user:
            channel = AUTH_CHANNEL_CLI_VIA_WEB if _is_cli_web_fallback_request(request) else AUTH_CHANNEL_WEB
            requested_client_channel = (request.POST.get("client_channel") or "").strip().lower()
            client_header = (request.headers.get("X-CIVault-Client") or "").strip().lower()
            channel = AUTH_CHANNEL_WEB
            if requested_client_channel == "cli" or client_header == "cli":
                channel = AUTH_CHANNEL_CLI_VIA_WEB

            _record_login_audit(request, user, auth_method, channel=channel)
            return redirect("vault_dashboard")

        return render(
            request,
            "login.html",
            {"error": error or "Authentication failed.", "selected_auth_method": auth_method},
        )

    return render(request, "login.html", {"selected_auth_method": AUTH_METHOD_USERNAME_PASSWORD})


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
        vault.save(update_fields=["is_sealed"])

    cache.set("vault_hard_sealed", True, None)
    request.session["vault_hard_sealed"] = True

    connections.close_all()
    logout(request)
    return render(request, "sealed.html")

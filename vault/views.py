import base64
import hmac
import logging
import os
import secrets
import hashlib
from urllib.parse import urlencode

from Crypto.Protocol.SecretSharing import Shamir
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import connections
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
import requests

from .crypto_utils import decrypt_root_key, encrypt_root_key
from .models import VaultConfig
from .security import get_client_ip, get_location_from_ip
from vault_dashboard.models import AppRole

logger = logging.getLogger(__name__)
SUPPORTED_LOGIN_METHODS = ("username_password", "approle", "github", "google")


def _complete_login(request, user, vault):
    login(request, user)
    request.session.cycle_key()
    if "vault_key" not in request.session:
        decrypted_root_key = decrypt_root_key(vault.encrypted_root_key)
        request.session["vault_key"] = base64.b64encode(decrypted_root_key).decode()
    request.session["auth_user"] = {
        "id": user.id,
        "username": user.username,
        "is_superuser": user.is_superuser,
    }
    return redirect("vault_dashboard")


def _get_oauth_provider_settings(request, provider_name):
    if provider_name == "github":
        return {
            "client_id": os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip(),
            "client_secret": os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip(),
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "userinfo_url": "https://api.github.com/user",
            "email_url": "https://api.github.com/user/emails",
            "scope": "read:user user:email",
        }
    if provider_name == "google":
        return {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip(),
            "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "scope": "openid email profile",
        }
    return None


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
        login_method = (request.POST.get("login_method") or "username_password").strip()

        if login_method not in SUPPORTED_LOGIN_METHODS:
            return render(request, "login.html", {"error": "Unsupported login method selected."})

        if login_method == "username_password":
            username = request.POST.get("username")
            password = request.POST.get("password")
            user = authenticate(request, username=username, password=password)
            if user:
                return _complete_login(request, user, vault)
            return render(request, "login.html", {"error": "Invalid username or password."})

        if login_method == "approle":
            role_id = (request.POST.get("role_id") or "").strip()
            secret_id = (request.POST.get("secret_id") or "").strip()
            approle = AppRole.objects.select_related("machine_policy__created_by").filter(role_id=role_id, is_active=True).first()
            if not approle:
                return render(request, "login.html", {"error": "Invalid Role ID."})
            if hashlib.sha256(secret_id.encode()).hexdigest() != approle.secret_id_hash:
                return render(request, "login.html", {"error": "Invalid Secret ID."})
            user = approle.machine_policy.created_by
            if not user or not user.is_active:
                return render(request, "login.html", {"error": "AppRole is not linked to an active user."})
            return _complete_login(request, user, vault)

    return render(request, "login.html", {"oauth_enabled": True})


def oauth_login_start(request, provider):
    vault = VaultConfig.objects.first()
    if not vault or vault.is_sealed:
        return render(request, "sealed.html")

    settings = _get_oauth_provider_settings(request, provider)
    if not settings:
        return render(request, "login.html", {"error": "Unsupported OAuth provider."})
    if not settings["client_id"] or not settings["client_secret"]:
        return render(request, "login.html", {"error": f"{provider.title()} OAuth is not configured on server."})

    state = secrets.token_urlsafe(24)
    request.session[f"{provider}_oauth_state"] = state
    callback_url = request.build_absolute_uri(reverse("oauth_login_callback", kwargs={"provider": provider}))

    if provider == "google":
        params = {
            "client_id": settings["client_id"],
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": settings["scope"],
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
    else:
        params = {
            "client_id": settings["client_id"],
            "redirect_uri": callback_url,
            "scope": settings["scope"],
            "state": state,
        }
    return redirect(f"{settings['authorize_url']}?{urlencode(params)}")


def oauth_login_callback(request, provider):
    vault = VaultConfig.objects.first()
    if not vault or vault.is_sealed:
        return render(request, "sealed.html")

    settings = _get_oauth_provider_settings(request, provider)
    if not settings:
        return render(request, "login.html", {"error": "Unsupported OAuth provider."})

    expected_state = request.session.pop(f"{provider}_oauth_state", None)
    if not expected_state or expected_state != request.GET.get("state"):
        return render(request, "login.html", {"error": "OAuth state validation failed. Please retry."})

    code = request.GET.get("code")
    if not code:
        return render(request, "login.html", {"error": "Authorization code missing from OAuth callback."})

    callback_url = request.build_absolute_uri(reverse("oauth_login_callback", kwargs={"provider": provider}))
    token_payload = {
        "client_id": settings["client_id"],
        "client_secret": settings["client_secret"],
        "code": code,
        "redirect_uri": callback_url,
    }
    if provider == "google":
        token_payload["grant_type"] = "authorization_code"

    token_headers = {"Accept": "application/json"}
    token_response = requests.post(settings["token_url"], data=token_payload, headers=token_headers, timeout=20)
    if token_response.status_code >= 400:
        return render(request, "login.html", {"error": f"{provider.title()} token exchange failed."})
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return render(request, "login.html", {"error": f"{provider.title()} access token missing."})

    user_headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    profile_response = requests.get(settings["userinfo_url"], headers=user_headers, timeout=20)
    if profile_response.status_code >= 400:
        return render(request, "login.html", {"error": f"Unable to fetch {provider.title()} profile."})
    profile = profile_response.json()

    email = profile.get("email")
    full_name = profile.get("name") or ""
    external_id = str(profile.get("id") or "")

    if provider == "github" and not email:
        email_response = requests.get(settings["email_url"], headers=user_headers, timeout=20)
        if email_response.status_code < 400:
            for row in email_response.json():
                if row.get("primary") or row.get("verified"):
                    email = row.get("email")
                    break

    if not email:
        return render(request, "login.html", {"error": f"{provider.title()} account did not provide an email."})

    user = User.objects.filter(email__iexact=email).first()
    if not user:
        safe_username = f"{provider}_{external_id or email.split('@')[0]}".lower().replace(" ", "_")
        base_username = safe_username[:140]
        candidate = base_username
        suffix = 1
        while User.objects.filter(username=candidate).exists():
            candidate = f"{base_username[:130]}_{suffix}"
            suffix += 1
        user = User.objects.create(username=candidate, email=email, first_name=full_name[:150])
        user.set_unusable_password()
        user.save()

    if not user.is_active:
        return render(request, "login.html", {"error": "This account is inactive."})
    return _complete_login(request, user, vault)


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

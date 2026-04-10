import base64
import hmac
import logging
import os

from Crypto.Protocol.SecretSharing import Shamir
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import connections
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from .crypto_utils import decrypt_root_key, encrypt_root_key
from .models import VaultConfig
from .security import get_client_ip, get_location_from_ip

logger = logging.getLogger(__name__)


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
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            request.session.cycle_key()
            request.session["auth_user"] = {
                "id": user.id,
                "username": user.username,
                "is_superuser": user.is_superuser,
            }
            return redirect("vault_dashboard")

        return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")


@login_required
def dashboard(request):
    vault = VaultConfig.objects.first()

    if vault and vault.is_sealed:
        logout(request)
        return render(request, "sealed.html")

    return render(request, "dashboard.html")


def logout_view(request):
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

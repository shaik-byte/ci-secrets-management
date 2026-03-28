import base64
import json
import os

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)

from .crypto_utils import decrypt_root_key, encrypt_root_key
from .models import VaultConfig, WebAuthnDevice
from .security import get_client_ip, get_location_from_ip

RP_ID = "localhost"
ORIGIN = "http://localhost:8000"
REQUIRED_WEBAUTHN_DEVICES = 2


def home(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return redirect("initialize")

    if vault.webauthn_devices.count() < REQUIRED_WEBAUTHN_DEVICES:
        return redirect("initialize")

    if vault.is_sealed:
        return redirect("unseal")

    if not request.user.is_authenticated:
        return redirect("login")

    return redirect("vault_dashboard")


def initialize_vault(request):
    vault = VaultConfig.objects.first()

    if not vault:
        location = get_location_from_ip(get_client_ip(request)) or "LOCALHOST"
        root_key = os.urandom(32)
        encrypted_root_key = encrypt_root_key(root_key)

        vault = VaultConfig.objects.create(
            encrypted_root_key=encrypted_root_key,
            allowed_location=location,
            is_sealed=True,
        )

    registered_count = vault.webauthn_devices.count()

    return render(
        request,
        "initialize.html",
        {
            "required_device_count": REQUIRED_WEBAUTHN_DEVICES,
            "registered_device_count": registered_count,
            "remaining_device_count": max(REQUIRED_WEBAUTHN_DEVICES - registered_count, 0),
        },
    )


def unseal_vault(request):
    vault = VaultConfig.objects.first()

    if not vault or vault.webauthn_devices.count() < REQUIRED_WEBAUTHN_DEVICES:
        return redirect("initialize")

    return render(
        request,
        "unseal.html",
        {
            "required_device_count": REQUIRED_WEBAUTHN_DEVICES,
            "registered_device_count": vault.webauthn_devices.count(),
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
    return redirect("login")


def seal_vault(request):
    vault = VaultConfig.objects.first()

    if vault:
        vault.is_sealed = True
        vault.save(update_fields=["is_sealed"])

    logout(request)
    return render(request, "sealed.html")


def begin_registration(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return JsonResponse({"error": "Vault not initialized"}, status=400)

    registered = list(vault.webauthn_devices.values_list("credential_id", flat=True))

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="CI Vault",
        user_id=b"vault_admin",
        user_name="vault_admin",
        user_display_name="Vault Admin",
        exclude_credentials=[
            {
                "type": "public-key",
                "id": credential_id,
            }
            for credential_id in registered
        ],
    )

    challenge_b64 = base64.urlsafe_b64encode(options.challenge).rstrip(b"=").decode()
    request.session["registration_challenge"] = challenge_b64

    return JsonResponse(
        {
            "challenge": challenge_b64,
            "rp": {
                "name": options.rp.name,
                "id": options.rp.id,
            },
            "user": {
                "id": base64.urlsafe_b64encode(options.user.id).rstrip(b"=").decode(),
                "name": options.user.name,
                "displayName": options.user.display_name,
            },
            "pubKeyCredParams": [
                {
                    "type": p.type,
                    "alg": p.alg,
                }
                for p in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "attestation": options.attestation,
            "requiredDevices": REQUIRED_WEBAUTHN_DEVICES,
            "registeredDevices": vault.webauthn_devices.count(),
        }
    )


@csrf_exempt
def finish_registration(request):
    try:
        data = json.loads(request.body)

        vault = VaultConfig.objects.first()
        if not vault:
            return JsonResponse({"error": "Vault not initialized"}, status=400)

        challenge_b64 = request.session.get("registration_challenge")
        if not challenge_b64:
            return JsonResponse({"error": "Registration challenge missing"}, status=400)

        padding = "=" * (-len(challenge_b64) % 4)
        expected_challenge = base64.urlsafe_b64decode(challenge_b64 + padding)

        verification = verify_registration_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

        device, created = WebAuthnDevice.objects.get_or_create(
            vault=vault,
            credential_id=verification.credential_id,
            defaults={
                "public_key": verification.credential_public_key,
                "sign_count": verification.sign_count,
            },
        )

        if not created:
            device.public_key = verification.credential_public_key
            device.sign_count = verification.sign_count
            device.save(update_fields=["public_key", "sign_count"])

        registered_count = vault.webauthn_devices.count()

        return JsonResponse(
            {
                "status": "registered",
                "registered_devices": registered_count,
                "required_devices": REQUIRED_WEBAUTHN_DEVICES,
                "ready_for_unseal": registered_count >= REQUIRED_WEBAUTHN_DEVICES,
            }
        )

    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=400)


def begin_authentication(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return JsonResponse({"error": "Vault not initialized"}, status=400)

    devices = list(vault.webauthn_devices.all())

    if len(devices) < REQUIRED_WEBAUTHN_DEVICES:
        return JsonResponse(
            {
                "error": f"Register at least {REQUIRED_WEBAUTHN_DEVICES} devices before unsealing.",
                "registered_devices": len(devices),
                "required_devices": REQUIRED_WEBAUTHN_DEVICES,
            },
            status=400,
        )

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            {
                "type": "public-key",
                "id": device.credential_id,
            }
            for device in devices
        ],
    )

    challenge_b64 = base64.urlsafe_b64encode(options.challenge).rstrip(b"=").decode()
    request.session["auth_challenge"] = challenge_b64

    return JsonResponse(
        {
            "challenge": challenge_b64,
            "rpId": options.rp_id,
            "timeout": options.timeout,
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(device.credential_id).rstrip(b"=").decode(),
                }
                for device in devices
            ],
            "userVerification": options.user_verification,
        }
    )


@csrf_exempt
def finish_authentication(request):
    try:
        data = json.loads(request.body)

        vault = VaultConfig.objects.first()
        if not vault:
            return JsonResponse({"error": "Vault not found"}, status=400)

        devices = list(vault.webauthn_devices.all())
        if len(devices) < REQUIRED_WEBAUTHN_DEVICES:
            return JsonResponse(
                {
                    "error": f"Register at least {REQUIRED_WEBAUTHN_DEVICES} devices before unsealing.",
                },
                status=400,
            )

        auth_challenge = request.session.get("auth_challenge")
        if not auth_challenge:
            return JsonResponse({"error": "No challenge in session"}, status=400)

        padding = "=" * (-len(auth_challenge) % 4)
        expected_challenge = base64.urlsafe_b64decode(auth_challenge + padding)

        raw_id_b64 = data.get("rawId")
        if not raw_id_b64:
            return JsonResponse({"error": "Missing credential id"}, status=400)

        credential_id = base64.b64decode(raw_id_b64)
        device = vault.webauthn_devices.filter(credential_id=credential_id).first()
        if not device:
            return JsonResponse({"error": "Unknown authenticator"}, status=400)

        verification = verify_authentication_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=device.public_key,
            credential_current_sign_count=device.sign_count,
        )

        decrypted_root_key = decrypt_root_key(vault.encrypted_root_key)
        request.session["vault_key"] = base64.b64encode(decrypted_root_key).decode()

        device.sign_count = verification.new_sign_count
        device.save(update_fields=["sign_count"])

        vault.is_sealed = False
        vault.save(update_fields=["is_sealed"])

        if "auth_challenge" in request.session:
            del request.session["auth_challenge"]

        return JsonResponse({"status": "unsealed"})

    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=400)

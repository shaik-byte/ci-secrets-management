from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import VaultConfig
from .security import get_client_ip, get_location_from_ip
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_exempt

from Crypto.Protocol.SecretSharing import Shamir
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import UserVerificationRequirement

from dataclasses import asdict
import os
import json
import base64


# =====================================================
# CONSTANTS (IMPORTANT)
# =====================================================

RP_ID = "localhost"
ORIGIN = "http://localhost:8000"


# =====================================================
# HOME
# =====================================================

def home(request):
    vault = VaultConfig.objects.first()

    if not vault:
        return redirect('initialize')

    if vault.is_sealed:
        return redirect('unseal')

    if not request.user.is_authenticated:
        return redirect('login')

    return redirect('vault_dashboard')


# =====================================================
# INITIALIZE
# =====================================================

# def initialize_vault(request):

#     if VaultConfig.objects.exists():
#         return redirect('unseal')

#     if request.method == "POST":

#         location = get_location_from_ip(get_client_ip(request)) or "LOCALHOST"

#         root_key = os.urandom(16)

#         shares_raw = Shamir.split(3, 5, root_key)

#         shares = []
#         for idx, share in shares_raw:
#             combined = idx.to_bytes(1, "big") + share
#             encoded = base64.urlsafe_b64encode(combined).decode()
#             shares.append(encoded)

#         VaultConfig.objects.create(
#             encrypted_root_key=root_key,
#             allowed_location=location,
#             is_sealed=True,
#         )

#         return render(request, "show_shares.html", {"shares": shares})

#     return render(request, "initialize.html")
from .crypto_utils import encrypt_root_key

def initialize_vault(request):

    vault = VaultConfig.objects.first()

    if not vault:
        location = get_location_from_ip(get_client_ip(request)) or "LOCALHOST"

        # Generate strong 256-bit root key
        root_key = os.urandom(32)

        # Encrypt root key using KEK
        encrypted_root_key = encrypt_root_key(root_key)

        vault = VaultConfig.objects.create(
            encrypted_root_key=encrypted_root_key,
            allowed_location=location,
            is_sealed=True,
        )

    return render(request, "initialize.html")


# =====================================================
# UNSEAL PAGE
# =====================================================

def unseal_vault(request):
    return render(request, "unseal.html")


# =====================================================
# LOGIN
# =====================================================

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
            return redirect('vault_dashboard')

        return render(request, "login.html", {"error": "Invalid credentials"})

    return render(request, "login.html")


# =====================================================
# DASHBOARD
# =====================================================

@login_required
def dashboard(request):
    vault = VaultConfig.objects.first()

    if vault.is_sealed:
        logout(request)
        return render(request, "sealed.html")

    return render(request, "dashboard.html")


# =====================================================
# LOGOUT
# =====================================================

def logout_view(request):
    logout(request)
    return redirect('login')


# =====================================================
# SEAL
# =====================================================

def seal_vault(request):
    vault = VaultConfig.objects.first()

    if vault:
        vault.is_sealed = True
        vault.save()

    logout(request)
    return render(request, "sealed.html")


# =====================================================
# BEGIN REGISTRATION
# =====================================================

# from dataclasses import asdict

# def begin_registration(request):

#     options = generate_registration_options(
#         rp_id=RP_ID,
#         rp_name="CI Vault",
#         user_id=b"vault_admin",
#         user_name="vault_admin",
#         user_display_name="Vault Admin",
#     )

#     request.session["registration_challenge"] = base64.b64encode(
#         options.challenge
#     ).decode()

#     return JsonResponse({
#         "challenge": base64.b64encode(options.challenge).decode(),
#         "rp": {
#             "name": options.rp.name,
#             "id": options.rp.id,
#         },
#         "user": {
#             "id": base64.b64encode(options.user.id).decode(),
#             "name": options.user.name,
#             "displayName": options.user.display_name,
#         },
#         "pubKeyCredParams": [
#             {
#                 "type": param.type,
#                 "alg": param.alg,
#             }
#             for param in options.pub_key_cred_params
#         ],
#         "timeout": options.timeout,
#         "attestation": options.attestation,
#     })

from webauthn import generate_registration_options
import base64

def begin_registration(request):

    options = generate_registration_options(
        rp_id="localhost",
        rp_name="CI Vault",
        user_id=b"vault_admin",
        user_name="vault_admin",
        user_display_name="Vault Admin",
    )

    # Store challenge in session (base64url without padding)
    challenge_b64 = base64.urlsafe_b64encode(options.challenge).rstrip(b"=").decode()
    request.session["registration_challenge"] = challenge_b64

    return JsonResponse({
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
            } for p in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
        "attestation": options.attestation,
    })



# =====================================================
# FINISH REGISTRATION
# =====================================================

# def finish_registration(request):
#     data = json.loads(request.body)
#     vault = VaultConfig.objects.first()

#     verification = verify_registration_response(
#         credential=data,
#         expected_challenge=request.session["registration_challenge"],
#         expected_rp_id=RP_ID,
#         expected_origin=ORIGIN,
#     )

#     vault.credential_id = verification.credential_id
#     vault.public_key = verification.credential_public_key
#     vault.sign_count = verification.sign_count
#     vault.save()

#     return JsonResponse({"status": "registered"})

@csrf_exempt
def finish_registration(request):
    try:
        data = json.loads(request.body)
        print("DATA RECEIVED:", data)

        vault = VaultConfig.objects.first()
        if not vault:
            return JsonResponse({"error": "Vault not initialized"}, status=400)

        challenge_b64 = request.session.get("registration_challenge")

        padding = '=' * (-len(challenge_b64) % 4)
        expected_challenge = base64.urlsafe_b64decode(challenge_b64 + padding)


        print("EXPECTED CHALLENGE:", expected_challenge)

        verification = verify_registration_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

        vault.credential_id = verification.credential_id
        vault.public_key = verification.credential_public_key
        vault.sign_count = verification.sign_count
        vault.save()

        return JsonResponse({"status": "registered"})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=400)

# =====================================================
# BEGIN AUTHENTICATION
# =====================================================

# def begin_authentication(request):
#     vault = VaultConfig.objects.first()

#     options = generate_authentication_options(
#         rp_id=RP_ID,
#         allow_credentials=[
#             {
#                 "type": "public-key",
#                 "id": vault.credential_id,
#             }
#         ],
#     )

#     request.session["auth_challenge"] = base64.b64encode(
#         options.challenge
#     ).decode()

#     options_dict = asdict(options)

#     options_dict["challenge"] = base64.b64encode(
#         options_dict["challenge"]
#     ).decode()

#     for cred in options_dict.get("allowCredentials", []):
#         cred["id"] = base64.b64encode(cred["id"]).decode()

#     return JsonResponse(options_dict)
def begin_authentication(request):
    vault = VaultConfig.objects.first()

    if not vault or not vault.credential_id:
        return JsonResponse({"error": "Device not registered"}, status=400)

    options = generate_authentication_options(
        rp_id="localhost",
        allow_credentials=[
            {
                "type": "public-key",
                "id": vault.credential_id,
            }
        ],
    )

    challenge_b64 = base64.urlsafe_b64encode(
        options.challenge
    ).rstrip(b"=").decode()

    request.session["auth_challenge"] = challenge_b64

    return JsonResponse({
        "challenge": challenge_b64,
        "rpId": options.rp_id,
        "timeout": options.timeout,
        "allowCredentials": [
            {
                "type": "public-key",
                "id": base64.urlsafe_b64encode(
                    vault.credential_id
                ).rstrip(b"=").decode(),
            }
        ],
        "userVerification": options.user_verification,
    })

# =====================================================
# FINISH AUTHENTICATION (UNSEAL HERE)
# =====================================================

from .crypto_utils import decrypt_root_key

@csrf_exempt
def finish_authentication(request):
    try:
        data = json.loads(request.body)

        vault = VaultConfig.objects.first()
        if not vault:
            return JsonResponse({"error": "Vault not found"}, status=400)
        
        print("SESSION CHALLENGE:", request.session.get("auth_challenge"))
        print("VAULT PUBLIC KEY:", vault.public_key)
        print("VAULT SIGN COUNT:", vault.sign_count)

        auth_challenge = request.session.get("auth_challenge")

        if not auth_challenge:
            return JsonResponse({"error": "No challenge in session"}, status=400)

        # Add padding back manually
        padding = '=' * (-len(auth_challenge) % 4)
        auth_challenge_padded = auth_challenge + padding

        expected_challenge = base64.urlsafe_b64decode(auth_challenge_padded)


        verification = verify_authentication_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id="localhost",
            expected_origin="http://localhost:8000",
            credential_public_key=vault.public_key,
            credential_current_sign_count=vault.sign_count,
        )

        decrypted_root_key = decrypt_root_key(vault.encrypted_root_key)

        request.session["vault_key"] = base64.b64encode(
            decrypted_root_key
        ).decode()

        vault.sign_count = verification.new_sign_count
        vault.is_sealed = False
        vault.save()

        # Clear challenge after use (important)
        del request.session["auth_challenge"]

        return JsonResponse({"status": "unsealed"})

    except Exception as e:
        print("AUTH ERROR:", str(e))
        return JsonResponse({"error": str(e)}, status=400)

# from django.shortcuts import render

# # Create your views here.
# from django.shortcuts import render, redirect, get_object_or_404
# from django.contrib.auth.decorators import login_required
from django.contrib import messages
# from .models import Environment, Folder, Secret, SecretPolicy
# from .utils import encrypt_value, decrypt_value
# from django.http import JsonResponse, HttpResponseForbidden
# from datetime import datetime
import re


# @login_required
# def dashboard(request):

#     if "vault_key" not in request.session:
#         return redirect("unseal")

#     environments = Environment.objects.filter(created_by=request.user)

#     return render(request, "vault_dashboard/dashboard.html", {
#         "environments": environments
#     })


# # @login_required
# # def add_environment(request):
# #     if request.method == "POST":
# #         name = request.POST.get("name")
# #         Environment.objects.create(name=name, created_by=request.user)
# #     return redirect("vault_dashboard")
# from auditlogs.models import AuditLog

# @login_required
# def add_environment(request):
#     if request.method == "POST":
#         name = request.POST.get("name")

#         env = Environment.objects.create(name=name, created_by=request.user)

#         # ✅ ADD THIS
#         AuditLog.objects.create(
#             user=request.user,
#             action='CREATE',
#             entity='Environment',
#             details=f"Created environment '{name}'"
#         )

#     return redirect("vault_dashboard")

# @login_required
# def add_folder(request, env_id):
#     env = get_object_or_404(Environment, id=env_id)

#     if request.method == "POST":
#         name = request.POST.get("name")
#         Folder.objects.create(name=name, environment=env)

#     return redirect("vault_dashboard")


# @login_required
# def add_secret(request, folder_id):
#     folder = get_object_or_404(Folder, id=folder_id)

#     if request.method == "POST":
#         name = request.POST.get("name")
#         value = request.POST.get("value")
#         expire = request.POST.get("expire")

#         encrypted = encrypt_value(request, value)
#         AuditLog.objects.create(
#         user=request.user,
#         action='CREATE',
#         entity='Secret',
#         details=f"Created secret '{name}' in folder '{folder.name}'"
#         )

#         Secret.objects.create(
#             name=name,
#             encrypted_value=encrypted,
#             expire_date=datetime.strptime(expire, "%Y-%m-%d") if expire else None,
#             folder=folder
#         )   

#     return redirect("vault_dashboard")


# @login_required
# def reveal_secret(request, secret_id):
#     secret = get_object_or_404(Secret, id=secret_id)

#     decrypted = decrypt_value(request, secret.encrypted_value)

#     return JsonResponse({"secret": decrypted})


# from django.contrib import messages

# @login_required
# def delete_environment(request, env_id):
#     env = get_object_or_404(Environment, id=env_id, created_by=request.user)

#     if request.method == "POST":
#         env.delete()

#     return redirect("vault_dashboard")

# @login_required
# def delete_folder(request, folder_id):
#     folder = get_object_or_404(
#         Folder,
#         id=folder_id,
#         environment__created_by=request.user
#     )

#     if request.method == "POST":
#         folder.delete()

#     return redirect("vault_dashboard")

# @login_required
# def delete_secret(request, secret_id):
#     secret = get_object_or_404(
#         Secret,
#         id=secret_id,
#         folder__environment__created_by=request.user
#     )

#     if request.method == "POST":
#         secret.delete()

#     return redirect("vault_dashboard")

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from datetime import datetime
import re

from .models import Environment, Folder, Secret, SecretPolicy
from .utils import encrypt_value, decrypt_value

from auditlogs.models import AuditLog


@login_required
def dashboard(request):

    if "vault_key" not in request.session:
        return redirect("unseal")

    environments = Environment.objects.filter(created_by=request.user)
    policy, _ = SecretPolicy.objects.get_or_create(created_by=request.user)

    return render(request, "vault_dashboard/dashboard.html", {
        "environments": environments,
        "secret_policy": policy,
    })


# =========================
# CREATE ENVIRONMENT
# =========================
@login_required
def add_environment(request):
    if request.method == "POST":
        name = request.POST.get("name")

        env = Environment.objects.create(name=name, created_by=request.user)

        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            entity='Environment',
            details=f"Created environment '{name}'",
            ip_address=get_client_ip(request)
        )

    return redirect("vault_dashboard")


# =========================
# CREATE FOLDER
# =========================
@login_required
def add_folder(request, env_id):
    env = get_object_or_404(Environment, id=env_id)

    if request.method == "POST":
        name = request.POST.get("name")
        owner_email = (request.POST.get("owner_email") or "").strip()

        folder = Folder.objects.create(name=name, owner_email=owner_email, environment=env)

        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            entity='Folder',
            details=f"Created folder '{name}' in environment '{env.name}'",
            ip_address=get_client_ip(request)
        )

    return redirect("vault_dashboard")


# =========================
# CREATE SECRET
# =========================
@login_required
def add_secret(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id)

    if request.method == "POST":
        name = request.POST.get("name")
        service_name = (request.POST.get("service_name") or "").strip()
        value = request.POST.get("value")
        expire = request.POST.get("expire")

        policy = SecretPolicy.objects.filter(created_by=request.user).first()
        regex_pattern = policy.secret_value_regex.strip() if policy else ""
        regex_mode = policy.regex_mode if policy else "match"

        if regex_pattern:
            try:
                is_match = bool(re.fullmatch(regex_pattern, value or ""))

                if regex_mode == "match" and not is_match:
                    messages.error(request, "Secret should match the configured regex policy.")
                    return redirect("vault_dashboard")

                if regex_mode == "not_match" and is_match:
                    messages.error(request, "Secret should not match the configured regex policy.")
                    return redirect("vault_dashboard")
            except re.error:
                messages.error(request, "Configured regex policy is invalid. Please update Settings.")
                return redirect("vault_dashboard")

        encrypted = encrypt_value(request, value)

        secret = Secret.objects.create(
            name=name,
            service_name=service_name,
            encrypted_value=encrypted,
            expire_date=datetime.strptime(expire, "%Y-%m-%d") if expire else None,
            folder=folder
        )

        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            entity='Secret',
            details=f"Created secret '{name}' in folder '{folder.name}'",
            ip_address=get_client_ip(request)
        )

    return redirect("vault_dashboard")


# =========================
# REVEAL SECRET
# =========================
@login_required
def reveal_secret(request, secret_id):
    secret = get_object_or_404(Secret, id=secret_id)

    if not secret.is_access_enabled and not request.user.is_superuser:
        return JsonResponse({"error": "Secret access is locked by admin."}, status=403)

    decrypted = decrypt_value(request, secret.encrypted_value)

    AuditLog.objects.create(
        user=request.user,
        action='REVEAL',
        entity='Secret',
        details=f"Revealed secret '{secret.name}'",
        ip_address=get_client_ip(request)
    )

    return JsonResponse({"secret": decrypted})


@login_required
def toggle_secret_access(request, secret_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")

    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin can change secret access")

    secret = get_object_or_404(Secret, id=secret_id)
    secret.is_access_enabled = not secret.is_access_enabled
    secret.save(update_fields=["is_access_enabled"])

    state = "enabled" if secret.is_access_enabled else "disabled"

    AuditLog.objects.create(
        user=request.user,
        action='UPDATE',
        entity='Secret',
        details=f"Admin {state} reveal access for secret '{secret.name}'",
        ip_address=get_client_ip(request)
    )

    return redirect("vault_dashboard")


# =========================
# DELETE ENVIRONMENT
# =========================
@login_required
def delete_environment(request, env_id):
    env = get_object_or_404(Environment, id=env_id, created_by=request.user)

    if request.method == "POST":

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            entity='Environment',
            details=f"Deleted environment '{env.name}'",
            ip_address=get_client_ip(request)
        )

        env.delete()

    return redirect("vault_dashboard")


# =========================
# DELETE FOLDER
# =========================
@login_required
def delete_folder(request, folder_id):
    folder = get_object_or_404(
        Folder,
        id=folder_id,
        environment__created_by=request.user
    )

    if request.method == "POST":

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            entity='Folder',
            details=f"Deleted folder '{folder.name}'",
            ip_address=get_client_ip(request)
        )

        folder.delete()

    return redirect("vault_dashboard")


# =========================
# DELETE SECRET
# =========================
@login_required
def delete_secret(request, secret_id):
    secret = get_object_or_404(
        Secret,
        id=secret_id,
        folder__environment__created_by=request.user
    )

    if request.method == "POST":

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            entity='Secret',
            details=f"Deleted secret '{secret.name}'",
            ip_address=get_client_ip(request)
        )

        secret.delete()

    return redirect("vault_dashboard")


@login_required
def save_secret_policy(request):
    if request.method == "POST":
        pattern = (request.POST.get("secret_value_regex") or "").strip()
        regex_mode = (request.POST.get("regex_mode") or "match").strip()

        if regex_mode not in {"match", "not_match"}:
            regex_mode = "match"

        if pattern:
            try:
                re.compile(pattern)
            except re.error:
                messages.error(request, "Invalid regex pattern. Please enter a valid regex.")
                return redirect("vault_dashboard")

        policy, _ = SecretPolicy.objects.get_or_create(created_by=request.user)
        policy.secret_value_regex = pattern
        policy.regex_mode = regex_mode
        policy.save(update_fields=["secret_value_regex", "regex_mode", "updated_at"])

        messages.success(request, "Secret regex policy saved successfully.")

    return redirect("vault_dashboard")


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')
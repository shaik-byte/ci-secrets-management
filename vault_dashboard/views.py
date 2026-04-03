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
from django.contrib.auth.models import User
from django.db.models import Q
from datetime import datetime
import json
import re
import yaml

from .models import Environment, Folder, Secret, SecretPolicy, AccessPolicy
from .utils import encrypt_value, decrypt_value

from auditlogs.models import AuditLog


def _action_field(action):
    return {
        "read": "can_read",
        "write": "can_write",
        "delete": "can_delete",
    }.get(action, "can_read")


def _has_access(user, action, environment=None, folder=None, secret=None):
    if user.is_superuser:
        return True

    if environment and environment.created_by_id == user.id:
        return True
    if folder and folder.environment.created_by_id == user.id:
        return True
    if secret and secret.folder.environment.created_by_id == user.id:
        return True

    action_field = _action_field(action)
    filters = Q(user=user)
    filters &= Q(**{action_field: True})

    scope = (
        Q(secret__isnull=True, folder__isnull=True, environment__isnull=True)
    )
    if environment:
        scope |= Q(environment=environment, folder__isnull=True, secret__isnull=True)
    if folder:
        scope |= Q(folder=folder, secret__isnull=True)
        scope |= Q(environment=folder.environment, folder__isnull=True, secret__isnull=True)
    if secret:
        scope |= Q(secret=secret)
        scope |= Q(folder=secret.folder, secret__isnull=True)
        scope |= Q(environment=secret.folder.environment, folder__isnull=True, secret__isnull=True)

    return AccessPolicy.objects.filter(filters & scope).exists()


@login_required
def dashboard(request):

    if "vault_key" not in request.session:
        return redirect("unseal")

    readable_env_ids = AccessPolicy.objects.filter(
        user=request.user,
        can_read=True,
        environment__isnull=False,
    ).values_list("environment_id", flat=True)
    environments = Environment.objects.filter(
        Q(created_by=request.user) | Q(id__in=readable_env_ids)
    ).distinct()
    policy, _ = SecretPolicy.objects.get_or_create(created_by=request.user)
    policy_presets = [
        {
            "key": "strong_password",
            "name": "Strong Password",
            "regex": r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,}$",
            "mode": "match",
            "description": "12+ chars with uppercase, lowercase, number, and symbol.",
        },
        {
            "key": "api_key_format",
            "name": "API Key Format",
            "regex": r"^[A-Za-z0-9_\-]{24,64}$",
            "mode": "match",
            "description": "Allow API-key style alphanumeric tokens (24-64 chars).",
        },
        {
            "key": "no_whitespace",
            "name": "No Whitespace",
            "regex": r"^\S+$",
            "mode": "match",
            "description": "Reject any secret value containing spaces/tabs/newlines.",
        },
        {
            "key": "block_placeholder_values",
            "name": "Block Placeholder Values",
            "regex": r"^(password|changeme|admin123|test123)$",
            "mode": "not_match",
            "description": "Disallow weak placeholder values.",
        },
    ]

    return render(request, "vault_dashboard/dashboard.html", {
        "environments": environments,
        "secret_policy": policy,
        "policy_presets": policy_presets,
        "users": User.objects.order_by("username"),
        "all_environments": Environment.objects.order_by("name"),
        "all_folders": Folder.objects.select_related("environment").order_by("name"),
        "all_secrets": Secret.objects.select_related("folder", "folder__environment").order_by("name"),
        "access_policies": AccessPolicy.objects.select_related("user", "environment", "folder", "secret").order_by("-updated_at")[:100],
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
    if not _has_access(request.user, "write", environment=env):
        return HttpResponseForbidden("You do not have write access to this environment.")

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
    if not _has_access(request.user, "write", folder=folder):
        return HttpResponseForbidden("You do not have write access to this folder.")

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
    if not _has_access(request.user, "read", secret=secret):
        return JsonResponse({"error": "You do not have read access for this secret."}, status=403)

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
    env = get_object_or_404(Environment, id=env_id)
    if not _has_access(request.user, "delete", environment=env):
        return HttpResponseForbidden("You do not have delete access to this environment.")

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
    folder = get_object_or_404(Folder, id=folder_id)
    if not _has_access(request.user, "delete", folder=folder):
        return HttpResponseForbidden("You do not have delete access to this folder.")

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
    secret = get_object_or_404(Secret, id=secret_id)
    if not _has_access(request.user, "delete", secret=secret):
        return HttpResponseForbidden("You do not have delete access to this secret.")

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


@login_required
def save_access_policy_ui(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin can manage policy engine access.")

    user_id = request.POST.get("user_id")
    environment_id = request.POST.get("environment_id") or None
    folder_id = request.POST.get("folder_id") or None
    secret_id = request.POST.get("secret_id") or None

    target_user = get_object_or_404(User, id=user_id)
    environment = Environment.objects.filter(id=environment_id).first() if environment_id else None
    folder = Folder.objects.filter(id=folder_id).first() if folder_id else None
    secret = Secret.objects.filter(id=secret_id).first() if secret_id else None

    can_read = bool(request.POST.get("can_read"))
    can_write = bool(request.POST.get("can_write"))
    can_delete = bool(request.POST.get("can_delete"))

    if not any([can_read, can_write, can_delete]):
        messages.error(request, "Please enable at least one permission: read, write, or delete.")
        return redirect("vault_dashboard")

    AccessPolicy.objects.update_or_create(
        user=target_user,
        environment=environment,
        folder=folder,
        secret=secret,
        defaults={
            "can_read": can_read,
            "can_write": can_write,
            "can_delete": can_delete,
        },
    )

    messages.success(request, f"Access policy updated for {target_user.username}.")
    return redirect("vault_dashboard")


@login_required
def save_access_policy_document(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin can manage policy engine access.")

    raw = (request.POST.get("policy_document") or "").strip()
    doc_format = (request.POST.get("document_format") or "json").strip().lower()

    if not raw:
        messages.error(request, "Policy document is empty.")
        return redirect("vault_dashboard")

    try:
        parsed = json.loads(raw) if doc_format == "json" else yaml.safe_load(raw)
    except Exception as exc:
        messages.error(request, f"Invalid {doc_format.upper()} policy document: {exc}")
        return redirect("vault_dashboard")

    rules = parsed.get("rules") if isinstance(parsed, dict) else None
    if not isinstance(rules, list):
        messages.error(request, "Policy document must contain a top-level 'rules' list.")
        return redirect("vault_dashboard")

    created = 0
    for rule in rules:
        username = (rule.get("user") or "").strip()
        if not username:
            continue
        target_user = User.objects.filter(username=username).first()
        if not target_user:
            continue

        environment = Environment.objects.filter(name=rule.get("environment")).first() if rule.get("environment") else None
        folder = Folder.objects.filter(name=rule.get("folder")).first() if rule.get("folder") else None
        secret = Secret.objects.filter(name=rule.get("secret")).first() if rule.get("secret") else None

        perms = rule.get("permissions") or {}
        AccessPolicy.objects.update_or_create(
            user=target_user,
            environment=environment,
            folder=folder,
            secret=secret,
            defaults={
                "can_read": bool(perms.get("read")),
                "can_write": bool(perms.get("write")),
                "can_delete": bool(perms.get("delete")),
            },
        )
        created += 1

    messages.success(request, f"Policy document processed. Updated {created} rule(s).")
    return redirect("vault_dashboard")


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

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
from django.core.cache import cache
from django.db.models import Q
from django.db import transaction
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from datetime import datetime, timedelta
from fnmatch import fnmatch
import json
import hashlib
import re
import secrets
import yaml
import requests
import jwt
from jwt import InvalidTokenError

from .models import (
    Environment,
    Folder,
    Secret,
    SecretPolicy,
    AccessPolicy,
    PolicyGroup,
    PolicyGroupMembership,
    PolicyGroupPolicy,
    MachinePolicy,
    AppRole,
    JWTWorkloadIdentity,
    MachineSessionToken,
    DeletionApprovalRequest,
    UserFeatureAccess,
    EnvironmentSecretPolicy,
)
from .utils import encrypt_value, decrypt_value
from .feature_access import FEATURE_CATALOG, FEATURE_DEFAULTS, resolve_user_feature_visibility, user_has_feature

from auditlogs.models import AuditLog

MACHINE_SESSION_TTL_SECONDS = 3600
JWKS_CACHE_TTL_SECONDS = 300


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
    group_policy_ids = PolicyGroupPolicy.objects.filter(
        group__memberships__user=user
    ).values_list("policy_id", flat=True)
    filters = Q(user=user) | Q(id__in=group_policy_ids)
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


def _manageable_environments_for_settings(user):
    if user.is_superuser:
        return Environment.objects.all()

    writable_ids = []
    for env in Environment.objects.all():
        if _has_access(user, "write", environment=env):
            writable_ids.append(env.id)
    return Environment.objects.filter(id__in=writable_ids)


@login_required
def dashboard(request):

    if "vault_key" not in request.session:
        return redirect("unseal")

    if request.user.is_superuser:
        environments = Environment.objects.select_related("created_by").all()
    else:
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

    users = User.objects.order_by("username")
    visible_feature_keys = resolve_user_feature_visibility(request.user)
    feature_rows = []
    if request.user.is_superuser:
        all_rules = UserFeatureAccess.objects.select_related("user").all()
        rules_by_user = {}
        for rule in all_rules:
            rules_by_user.setdefault(rule.user_id, {})[rule.feature_key] = rule.can_view

        for target_user in users:
            explicit = rules_by_user.get(target_user.id, {})
            row = []
            for feature in FEATURE_CATALOG:
                key = feature["key"]
                default_enabled = feature["default_enabled"]
                effective_enabled = True if target_user.is_superuser else explicit.get(key, default_enabled)
                row.append({
                    "key": key,
                    "label": feature["label"],
                    "enabled": effective_enabled,
                    "locked": target_user.is_superuser,
                })
            feature_rows.append({"user": target_user, "features": row})

    all_secrets = Secret.objects.select_related("folder", "folder__environment").order_by("name")
    env_policy_map = {
        p.environment_id: p for p in EnvironmentSecretPolicy.objects.select_related("environment")
    }
    for env in environments:
        env.secret_value_regex = env_policy_map.get(env.id).secret_value_regex if env.id in env_policy_map else policy.secret_value_regex
        env.regex_mode = env_policy_map.get(env.id).regex_mode if env.id in env_policy_map else policy.regex_mode

    effective_access_rows = []
    for user in users:
        readable = []
        for s in all_secrets:
            if _has_access(user, "read", secret=s):
                readable.append(f"{s.folder.environment.name}/{s.folder.name}/{s.name}")
        effective_access_rows.append({
            "user": user,
            "readable_secrets": readable[:15],
            "extra_count": max(len(readable) - 15, 0),
        })

    return render(request, "vault_dashboard/dashboard.html", {
        "environments": environments,
        "secret_policy": policy,
        "policy_presets": policy_presets,
        "users": users,
        "all_environments": Environment.objects.order_by("name"),
        "all_folders": Folder.objects.select_related("environment").order_by("name"),
        "all_secrets": all_secrets,
        "access_policies": AccessPolicy.objects.select_related("user", "environment", "folder", "secret").order_by("-updated_at")[:100],
        "policy_groups": PolicyGroup.objects.select_related("created_by").prefetch_related("memberships__user", "policy_links__policy").order_by("name"),
        "effective_access_rows": effective_access_rows,
        "machine_policies": MachinePolicy.objects.select_related("access_policy").order_by("name"),
        "approles": AppRole.objects.select_related("machine_policy").order_by("name"),
        "jwt_identities": JWTWorkloadIdentity.objects.select_related("machine_policy").order_by("name"),
        "new_approle_secret": request.session.pop("new_approle_secret", None),
        "new_approle_role_name": request.session.pop("new_approle_role_name", None),
        "pending_deletion_approvals": DeletionApprovalRequest.objects.select_related("requested_by").filter(status="pending")[:100] if "approvals" in visible_feature_keys else [],
        "recent_deletion_approvals": DeletionApprovalRequest.objects.select_related("requested_by", "approver").exclude(status="pending")[:100] if "approvals" in visible_feature_keys else [],
        "can_view_secrets": "secrets" in visible_feature_keys,
        "can_view_settings": "settings" in visible_feature_keys,
        "can_view_policy": "policy" in visible_feature_keys,
        "can_view_approvals": "approvals" in visible_feature_keys,
        "can_view_notifications": "notifications" in visible_feature_keys,
        "can_view_audit_logs": "audit_logs" in visible_feature_keys,
        "can_view_seal_vault": "seal_vault" in visible_feature_keys,
        "feature_rows": feature_rows,
        "setting_environments": _manageable_environments_for_settings(request.user).order_by("name"),
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

        fallback_policy = SecretPolicy.objects.filter(created_by=request.user).first()
        env_policy = EnvironmentSecretPolicy.objects.filter(environment=folder.environment).first()
        policy = env_policy if (env_policy and env_policy.secret_value_regex) else fallback_policy
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


def _within_search_rate_limit(user_id, limit=30, window_seconds=60):
    cache_key = f"secret-path-search:{user_id}"
    current = cache.get(cache_key, 0)
    if current >= limit:
        return False
    cache.set(cache_key, current + 1, timeout=window_seconds)
    return True


@login_required
@require_GET
def search_secret_paths(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)

    if not _within_search_rate_limit(request.user.id):
        return JsonResponse({"error": "Too many search requests. Please retry shortly."}, status=429)

    query = (request.GET.get("q") or "").strip()
    mode = (request.GET.get("mode") or "name").strip().lower()
    if mode not in {"name", "value_exact"}:
        mode = "name"

    if len(query) < 2:
        return JsonResponse({"error": "Enter at least 2 characters to search."}, status=400)
    if len(query) > 200:
        return JsonResponse({"error": "Search query is too long."}, status=400)

    search_scope = Secret.objects.select_related("folder", "folder__environment").order_by("name")
    if mode == "name":
        search_scope = search_scope.filter(
            Q(name__icontains=query)
            | Q(service_name__icontains=query)
            | Q(folder__name__icontains=query)
            | Q(folder__environment__name__icontains=query)
        )

    max_scan = 600 if mode == "name" else 250
    scanned = 0
    matches = []
    for secret in search_scope[:max_scan]:
        scanned += 1
        if not _has_access(request.user, "read", secret=secret):
            continue

        if mode == "value_exact":
            try:
                candidate = decrypt_value(request, secret.encrypted_value)
            except Exception:
                continue
            if not secrets.compare_digest(candidate, query):
                continue

        matches.append({
            "secret_id": secret.id,
            "environment": secret.folder.environment.name,
            "folder": secret.folder.name,
            "secret_name": secret.name,
            "service_name": secret.service_name,
            "path": f"{secret.folder.environment.name}/{secret.folder.name}/{secret.name}",
            "reveal_enabled": bool(secret.is_access_enabled or request.user.is_superuser),
        })
        if len(matches) >= 50:
            break

    AuditLog.objects.create(
        user=request.user,
        action="READ",
        entity="SecretSearch",
        details=f"Searched secret paths using mode={mode}, query_len={len(query)}, results={len(matches)}",
        ip_address=get_client_ip(request),
    )

    return JsonResponse({
        "results": matches,
        "mode": mode,
        "count": len(matches),
        "truncated": len(matches) >= 50 or scanned >= max_scan,
    })


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


def _create_deletion_approval(request, target_type, target_obj, note=""):
    existing = DeletionApprovalRequest.objects.filter(
        target_type=target_type,
        target_id=target_obj.id,
        requested_by=request.user,
        status="pending",
    ).first()
    if existing:
        messages.info(request, f"Deletion approval is already pending for {target_type} '{target_obj}'.")
        return existing

    approval = DeletionApprovalRequest.objects.create(
        target_type=target_type,
        target_id=target_obj.id,
        target_name=str(target_obj),
        requested_by=request.user,
        request_note=note or "",
    )
    messages.success(request, f"Deletion request submitted for approval: {target_type} '{target_obj}'.")
    return approval


def _resolve_delete_target(approval):
    if approval.target_type == "environment":
        return Environment.objects.filter(id=approval.target_id).first()
    if approval.target_type == "folder":
        return Folder.objects.filter(id=approval.target_id).first()
    if approval.target_type == "secret":
        return Secret.objects.filter(id=approval.target_id).first()
    return None


def _should_route_delete_to_approval(user, environment):
    return (not user.is_superuser) and bool(environment.require_admin_delete_approval)


# =========================
# DELETE ENVIRONMENT
# =========================
@login_required
def delete_environment(request, env_id):
    env = get_object_or_404(Environment, id=env_id)
    if not _has_access(request.user, "delete", environment=env):
        return HttpResponseForbidden("You do not have delete access to this environment.")

    if request.method == "POST":
        if _should_route_delete_to_approval(request.user, env):
            approval = _create_deletion_approval(request, "environment", env)
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                entity='Environment',
                details=f"Requested deletion approval for environment '{env.name}' (request #{approval.id})",
                ip_address=get_client_ip(request)
            )
            return redirect("vault_dashboard")

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
        if _should_route_delete_to_approval(request.user, folder.environment):
            approval = _create_deletion_approval(request, "folder", folder)
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                entity='Folder',
                details=f"Requested deletion approval for folder '{folder.name}' (request #{approval.id})",
                ip_address=get_client_ip(request)
            )
            return redirect("vault_dashboard")

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
        if _should_route_delete_to_approval(request.user, secret.folder.environment):
            approval = _create_deletion_approval(request, "secret", secret)
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                entity='Secret',
                details=f"Requested deletion approval for secret '{secret.name}' (request #{approval.id})",
                ip_address=get_client_ip(request)
            )
            return redirect("vault_dashboard")

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
def approve_deletion_request(request, approval_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "approvals"):
        return HttpResponseForbidden("You do not have approvals feature access.")

    approval = get_object_or_404(DeletionApprovalRequest, id=approval_id, status="pending")
    target_obj = _resolve_delete_target(approval)

    if not target_obj:
        approval.status = "rejected"
        approval.approver = request.user
        approval.decision_note = "Target no longer exists."
        approval.decided_at = timezone.now()
        approval.save(update_fields=["status", "approver", "decision_note", "decided_at", "updated_at"])
        messages.warning(request, f"Request #{approval.id} rejected because target no longer exists.")
        return redirect("vault_dashboard")

    with transaction.atomic():
        approval.status = "approved"
        approval.approver = request.user
        approval.decision_note = "Approved by root user."
        approval.decided_at = timezone.now()
        approval.save(update_fields=["status", "approver", "decision_note", "decided_at", "updated_at"])

        target_name = str(target_obj)
        target_obj.delete()

        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            entity=approval.target_type.capitalize(),
            details=f"Approved request #{approval.id} and deleted '{target_name}' requested by '{approval.requested_by.username}'",
            ip_address=get_client_ip(request)
        )

    messages.success(request, f"Approved request #{approval.id}. Deletion executed.")
    return redirect("vault_dashboard")


@login_required
def reject_deletion_request(request, approval_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "approvals"):
        return HttpResponseForbidden("You do not have approvals feature access.")

    approval = get_object_or_404(DeletionApprovalRequest, id=approval_id, status="pending")
    approval.status = "rejected"
    approval.approver = request.user
    approval.decision_note = "Rejected by root user."
    approval.decided_at = timezone.now()
    approval.save(update_fields=["status", "approver", "decision_note", "decided_at", "updated_at"])

    AuditLog.objects.create(
        user=request.user,
        action='UPDATE',
        entity=approval.target_type.capitalize(),
        details=f"Rejected deletion request #{approval.id} for '{approval.target_name}' from '{approval.requested_by.username}'",
        ip_address=get_client_ip(request)
    )

    messages.info(request, f"Rejected request #{approval.id}.")
    return redirect("vault_dashboard")


@login_required
def toggle_environment_delete_approval(request, env_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "approvals"):
        return HttpResponseForbidden("You do not have approvals feature access.")

    env = get_object_or_404(Environment, id=env_id)
    env.require_admin_delete_approval = not env.require_admin_delete_approval
    env.save(update_fields=["require_admin_delete_approval"])

    state = "enabled" if env.require_admin_delete_approval else "disabled"
    AuditLog.objects.create(
        user=request.user,
        action='UPDATE',
        entity='Environment',
        details=f"Admin {state} manual delete approval mode for environment '{env.name}'",
        ip_address=get_client_ip(request)
    )
    messages.success(request, f"Manual delete approval {state} for environment '{env.name}'.")
    return redirect("vault_dashboard")


@login_required
def save_secret_policy(request):
    if not user_has_feature(request.user, "settings"):
        return HttpResponseForbidden("You do not have settings feature access.")

    if request.method == "POST":
        pattern = (request.POST.get("secret_value_regex") or "").strip()
        regex_mode = (request.POST.get("regex_mode") or "match").strip()
        apply_all = bool(request.POST.get("apply_all_environments"))
        selected_env_ids = request.POST.getlist("environment_ids")

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

        manageable_envs = _manageable_environments_for_settings(request.user)
        if apply_all:
            target_envs = manageable_envs
        else:
            target_envs = manageable_envs.filter(id__in=selected_env_ids)
            if not target_envs.exists():
                messages.error(request, "Select at least one environment or choose Apply All Environments.")
                return redirect("vault_dashboard")

        with transaction.atomic():
            for env in target_envs:
                EnvironmentSecretPolicy.objects.update_or_create(
                    environment=env,
                    defaults={
                        "secret_value_regex": pattern,
                        "regex_mode": regex_mode,
                        "updated_by": request.user,
                    },
                )

        messages.success(request, f"Secret regex policy applied to {target_envs.count()} environment(s).")

    return redirect("vault_dashboard")


@login_required
def save_feature_access(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin can manage feature visibility.")

    user_id = request.POST.get("user_id")
    target_user = get_object_or_404(User, id=user_id)
    if target_user.is_superuser:
        messages.info(request, "Superusers always retain access to all features.")
        return redirect("vault_dashboard")

    selected = set(request.POST.getlist("enabled_features"))
    allowed_keys = set(FEATURE_DEFAULTS.keys())

    with transaction.atomic():
        for key in allowed_keys:
            desired = key in selected
            default_value = FEATURE_DEFAULTS.get(key, False)
            if desired == default_value:
                UserFeatureAccess.objects.filter(user=target_user, feature_key=key).delete()
            else:
                UserFeatureAccess.objects.update_or_create(
                    user=target_user,
                    feature_key=key,
                    defaults={"can_view": desired},
                )

    messages.success(request, f"Updated feature visibility for '{target_user.username}'.")
    return redirect("vault_dashboard")


@login_required
def save_access_policy_ui(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    policy_id = request.POST.get("policy_id")
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

    defaults = {
        "can_read": can_read,
        "can_write": can_write,
        "can_delete": can_delete,
    }
    if policy_id:
        policy = AccessPolicy.objects.filter(id=policy_id).first()
        if policy:
            policy.user = target_user
            policy.environment = environment
            policy.folder = folder
            policy.secret = secret
            policy.can_read = can_read
            policy.can_write = can_write
            policy.can_delete = can_delete
            policy.save(update_fields=["user", "environment", "folder", "secret", "can_read", "can_write", "can_delete", "updated_at"])
        else:
            AccessPolicy.objects.create(
                user=target_user,
                environment=environment,
                folder=folder,
                secret=secret,
                **defaults,
            )
    else:
        AccessPolicy.objects.update_or_create(
            user=target_user,
            environment=environment,
            folder=folder,
            secret=secret,
            defaults=defaults,
        )

    messages.success(request, f"Access policy updated for {target_user.username}.")
    return redirect("vault_dashboard")


@login_required
def save_access_policy_document(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

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


@login_required
def delete_access_policy(request, policy_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    policy = get_object_or_404(AccessPolicy, id=policy_id)
    policy.delete()
    messages.success(request, "Access policy deleted successfully.")
    return redirect("vault_dashboard")


@login_required
def create_policy_group(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    name = (request.POST.get("name") or "").strip()
    description = (request.POST.get("description") or "").strip()
    if not name:
        messages.error(request, "Group name is required.")
        return redirect("vault_dashboard")

    PolicyGroup.objects.update_or_create(
        name=name,
        defaults={"description": description, "created_by": request.user},
    )
    messages.success(request, f"Policy group '{name}' saved.")
    return redirect("vault_dashboard")


@login_required
def add_user_to_policy_group(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    group = get_object_or_404(PolicyGroup, id=request.POST.get("group_id"))
    user = get_object_or_404(User, id=request.POST.get("user_id"))
    PolicyGroupMembership.objects.get_or_create(group=group, user=user)
    messages.success(request, f"Added {user.username} to group {group.name}.")
    return redirect("vault_dashboard")


@login_required
def remove_user_from_policy_group(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    group = get_object_or_404(PolicyGroup, id=request.POST.get("group_id"))
    user = get_object_or_404(User, id=request.POST.get("user_id"))
    PolicyGroupMembership.objects.filter(group=group, user=user).delete()
    messages.success(request, f"Removed {user.username} from group {group.name}.")
    return redirect("vault_dashboard")


@login_required
def attach_policy_to_group(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    group = get_object_or_404(PolicyGroup, id=request.POST.get("group_id"))
    policy = get_object_or_404(AccessPolicy, id=request.POST.get("policy_id"))
    PolicyGroupPolicy.objects.get_or_create(group=group, policy=policy)
    messages.success(request, f"Attached policy #{policy.id} to group {group.name}.")
    return redirect("vault_dashboard")


@login_required
def detach_policy_from_group(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    group = get_object_or_404(PolicyGroup, id=request.POST.get("group_id"))
    policy = get_object_or_404(AccessPolicy, id=request.POST.get("policy_id"))
    PolicyGroupPolicy.objects.filter(group=group, policy=policy).delete()
    messages.success(request, f"Detached policy #{policy.id} from group {group.name}.")
    return redirect("vault_dashboard")


@login_required
def save_policy_groups_document(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    raw = (request.POST.get("group_policy_document") or "").strip()
    doc_format = (request.POST.get("group_document_format") or "json").strip().lower()
    if not raw:
        messages.error(request, "Group policy document is empty.")
        return redirect("vault_dashboard")

    try:
        parsed = json.loads(raw) if doc_format == "json" else yaml.safe_load(raw)
    except Exception as exc:
        messages.error(request, f"Invalid {doc_format.upper()} group policy document: {exc}")
        return redirect("vault_dashboard")

    groups = parsed.get("groups") if isinstance(parsed, dict) else None
    if not isinstance(groups, list):
        messages.error(request, "Group policy document must contain top-level 'groups' list.")
        return redirect("vault_dashboard")

    updated = 0
    for item in groups:
        name = (item.get("name") or "").strip()
        if not name:
            continue
        description = (item.get("description") or "").strip()
        group, _ = PolicyGroup.objects.update_or_create(
            name=name,
            defaults={"description": description, "created_by": request.user},
        )

        users = item.get("users") or []
        if isinstance(users, list):
            PolicyGroupMembership.objects.filter(group=group).exclude(
                user__username__in=[u for u in users if isinstance(u, str)]
            ).delete()
            for username in users:
                if not isinstance(username, str):
                    continue
                user_obj = User.objects.filter(username=username).first()
                if user_obj:
                    PolicyGroupMembership.objects.get_or_create(group=group, user=user_obj)

        policy_ids = item.get("policy_ids") or []
        if isinstance(policy_ids, list):
            valid_ids = [pid for pid in policy_ids if isinstance(pid, int)]
            PolicyGroupPolicy.objects.filter(group=group).exclude(policy_id__in=valid_ids).delete()
            for pid in valid_ids:
                policy = AccessPolicy.objects.filter(id=pid).first()
                if policy:
                    PolicyGroupPolicy.objects.get_or_create(group=group, policy=policy)

        updated += 1

    messages.success(request, f"Group policy document processed. Updated {updated} group(s).")
    return redirect("vault_dashboard")


def _normalize_audience(aud_claim):
    if isinstance(aud_claim, list):
        return [str(a) for a in aud_claim]
    if aud_claim in (None, ""):
        return []
    return [str(aud_claim)]


def _get_signing_key_from_jwks(jwks_url, kid):
    cache_key = f"jwks_cache:{hashlib.sha256(jwks_url.encode()).hexdigest()}"
    jwks = cache.get(cache_key)
    if not jwks:
        response = requests.get(jwks_url, timeout=5)
        response.raise_for_status()
        jwks = response.json()
        cache.set(cache_key, jwks, JWKS_CACHE_TTL_SECONDS)

    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return jwt.PyJWK.from_dict(key).key

    if len(keys) == 1:
        return jwt.PyJWK.from_dict(keys[0]).key

    raise ValueError("Unable to resolve signing key from JWKS.")


def _build_scope_payload(access_policy):
    scope = "global"
    if access_policy.secret_id:
        scope = f"secret:{access_policy.secret_id}"
    elif access_policy.folder_id:
        scope = f"folder:{access_policy.folder_id}"
    elif access_policy.environment_id:
        scope = f"environment:{access_policy.environment_id}"

    return {
        "scope": scope,
        "can_read": access_policy.can_read,
        "can_write": access_policy.can_write,
        "can_delete": access_policy.can_delete,
    }


@csrf_exempt
def jwt_machine_login(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST method required."}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    token = (payload.get("jwt") or payload.get("token") or "").strip()
    identity_name = (payload.get("identity_name") or "").strip()
    if not token:
        return JsonResponse({"error": "Field 'jwt' is required."}, status=400)

    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as exc:
        return JsonResponse({"error": f"Invalid JWT format: {exc}"}, status=400)

    issuer = str(unverified_claims.get("iss") or "").strip()
    subject = str(unverified_claims.get("sub") or "").strip()
    audiences = _normalize_audience(unverified_claims.get("aud"))
    kid = unverified_header.get("kid")
    if not issuer:
        return JsonResponse({"error": "JWT 'iss' claim is required."}, status=400)
    if not audiences:
        return JsonResponse({"error": "JWT 'aud' claim is required."}, status=400)

    identities = JWTWorkloadIdentity.objects.select_related("machine_policy", "machine_policy__access_policy").filter(
        issuer=issuer,
        audience__in=audiences,
        is_active=True,
    )
    if identity_name:
        identities = identities.filter(name=identity_name)
    identities = list(identities)
    if not identities:
        return JsonResponse({"error": "No active JWT workload identity matches this token."}, status=403)

    verified_identity = None
    verified_claims = None
    for identity in identities:
        if identity.subject_pattern and not fnmatch(subject, identity.subject_pattern):
            continue
        if not identity.jwks_url:
            continue
        try:
            key = _get_signing_key_from_jwks(identity.jwks_url, kid)
            verified = jwt.decode(
                token,
                key=key,
                algorithms=[unverified_header.get("alg", "RS256")],
                audience=identity.audience,
                issuer=identity.issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except (InvalidTokenError, ValueError, requests.RequestException):
            continue
        verified_identity = identity
        verified_claims = verified
        break

    if not verified_identity:
        return JsonResponse({"error": "JWT verification failed for all matching identities."}, status=403)

    raw_machine_token = f"mvt_{secrets.token_urlsafe(48)}"
    machine_token_hash = hashlib.sha256(raw_machine_token.encode()).hexdigest()
    expires_at = timezone.now() + timedelta(seconds=MACHINE_SESSION_TTL_SECONDS)
    MachineSessionToken.objects.create(
        token_hash=machine_token_hash,
        machine_policy=verified_identity.machine_policy,
        jwt_identity=verified_identity,
        subject=str(verified_claims.get("sub") or ""),
        issuer=str(verified_claims.get("iss") or ""),
        audience=verified_identity.audience,
        jwt_id=str(verified_claims.get("jti") or ""),
        claims_snapshot={
            "sub": verified_claims.get("sub"),
            "iss": verified_claims.get("iss"),
            "aud": verified_claims.get("aud"),
        },
        expires_at=expires_at,
        is_active=True,
    )

    access_policy = verified_identity.machine_policy.access_policy
    return JsonResponse(
        {
            "machine_token": raw_machine_token,
            "token_type": "Bearer",
            "expires_at": expires_at.isoformat(),
            "expires_in": MACHINE_SESSION_TTL_SECONDS,
            "identity": verified_identity.name,
            "machine_policy": verified_identity.machine_policy.name,
            "access": _build_scope_payload(access_policy),
        },
        status=200,
    )


@login_required
def save_machine_policy(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    name = (request.POST.get("name") or "").strip()
    description = (request.POST.get("description") or "").strip()
    access_policy = get_object_or_404(AccessPolicy, id=request.POST.get("access_policy_id"))
    if not name:
        messages.error(request, "Machine policy name is required.")
        return redirect("vault_dashboard")

    MachinePolicy.objects.update_or_create(
        name=name,
        defaults={
            "description": description,
            "access_policy": access_policy,
            "created_by": request.user,
        },
    )
    messages.success(request, f"Machine policy '{name}' saved.")
    return redirect("vault_dashboard")


@login_required
def save_approle(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    name = (request.POST.get("name") or "").strip()
    if not name:
        messages.error(request, "AppRole name is required.")
        return redirect("vault_dashboard")

    machine_policy = get_object_or_404(MachinePolicy, id=request.POST.get("machine_policy_id"))
    secret_id_plain = secrets.token_urlsafe(32)
    secret_id_hash = hashlib.sha256(secret_id_plain.encode()).hexdigest()
    bound_cidrs = (request.POST.get("bound_cidrs") or "").strip()
    ttl = int(request.POST.get("token_ttl_seconds") or 3600)
    is_active = bool(request.POST.get("is_active"))

    AppRole.objects.update_or_create(
        name=name,
        defaults={
            "machine_policy": machine_policy,
            "secret_id_hash": secret_id_hash,
            "bound_cidrs": bound_cidrs,
            "token_ttl_seconds": ttl,
            "is_active": is_active,
        },
    )

    request.session["new_approle_secret"] = secret_id_plain
    request.session["new_approle_role_name"] = name
    messages.success(request, f"AppRole '{name}' saved. Copy generated Secret ID now.")
    return redirect("vault_dashboard")


@login_required
def save_jwt_workload_identity(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    name = (request.POST.get("name") or "").strip()
    if not name:
        messages.error(request, "JWT identity name is required.")
        return redirect("vault_dashboard")

    machine_policy = get_object_or_404(MachinePolicy, id=request.POST.get("machine_policy_id"))
    JWTWorkloadIdentity.objects.update_or_create(
        name=name,
        defaults={
            "issuer": (request.POST.get("issuer") or "").strip(),
            "audience": (request.POST.get("audience") or "").strip(),
            "subject_pattern": (request.POST.get("subject_pattern") or "").strip(),
            "jwks_url": (request.POST.get("jwks_url") or "").strip(),
            "machine_policy": machine_policy,
            "is_active": bool(request.POST.get("is_active")),
        },
    )
    messages.success(request, f"JWT workload identity '{name}' saved.")
    return redirect("vault_dashboard")


@login_required
def save_machine_auth_document(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if not user_has_feature(request.user, "policy"):
        return HttpResponseForbidden("You do not have policy engine feature access.")

    raw = (request.POST.get("machine_auth_document") or "").strip()
    doc_format = (request.POST.get("machine_auth_format") or "json").strip().lower()
    if not raw:
        messages.error(request, "Machine auth document is empty.")
        return redirect("vault_dashboard")

    try:
        parsed = json.loads(raw) if doc_format == "json" else yaml.safe_load(raw)
    except Exception as exc:
        messages.error(request, f"Invalid {doc_format.upper()} machine auth document: {exc}")
        return redirect("vault_dashboard")

    updated = 0
    for item in parsed.get("machine_policies", []):
        mp_name = (item.get("name") or "").strip()
        if not mp_name:
            continue
        access_policy = AccessPolicy.objects.filter(id=item.get("access_policy_id")).first()
        if not access_policy:
            continue
        mp, _ = MachinePolicy.objects.update_or_create(
            name=mp_name,
            defaults={
                "description": (item.get("description") or "").strip(),
                "access_policy": access_policy,
                "created_by": request.user,
            },
        )
        for ar in item.get("approles", []):
            ar_name = (ar.get("name") or "").strip()
            if not ar_name:
                continue
            secret_id_plain = secrets.token_urlsafe(32)
            AppRole.objects.update_or_create(
                name=ar_name,
                defaults={
                    "machine_policy": mp,
                    "secret_id_hash": hashlib.sha256(secret_id_plain.encode()).hexdigest(),
                    "bound_cidrs": (ar.get("bound_cidrs") or "").strip(),
                    "token_ttl_seconds": int(ar.get("token_ttl_seconds") or 3600),
                    "is_active": bool(ar.get("is_active", True)),
                },
            )
        for jw in item.get("jwt_identities", []):
            jw_name = (jw.get("name") or "").strip()
            if not jw_name:
                continue
            JWTWorkloadIdentity.objects.update_or_create(
                name=jw_name,
                defaults={
                    "issuer": (jw.get("issuer") or "").strip(),
                    "audience": (jw.get("audience") or "").strip(),
                    "subject_pattern": (jw.get("subject_pattern") or "").strip(),
                    "jwks_url": (jw.get("jwks_url") or "").strip(),
                    "machine_policy": mp,
                    "is_active": bool(jw.get("is_active", True)),
                },
            )
        updated += 1

    messages.success(request, f"Machine auth document processed. Updated {updated} machine policy set(s).")
    return redirect("vault_dashboard")


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

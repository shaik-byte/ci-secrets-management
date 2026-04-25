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
import logging


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
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db.models import Q, Count, Avg, Max
from django.db import transaction
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    AnalysisIncident,
    AnalysisSavedQuery,
)
from .utils import encrypt_value, decrypt_value
from .feature_access import FEATURE_CATALOG, FEATURE_DEFAULTS, resolve_user_feature_visibility, user_has_feature
from .analysis import VaultAnalysisOrchestrator, AuditLogNLQueryEngine
from .analysis.alerting import AlertingRouter

from auditlogs.models import AuditLog

MACHINE_SESSION_TTL_SECONDS = 3600
JWKS_CACHE_TTL_SECONDS = 300
logger = logging.getLogger(__name__)


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


def _visible_environments_for_user(user):
    environments = Environment.objects.select_related("created_by").prefetch_related("folders__secrets").all()
    visible_environments = []

    for env in environments:
        all_folders = list(env.folders.all())
        if user.is_superuser or env.created_by_id == user.id:
            for folder in all_folders:
                folder.visible_secrets = list(folder.secrets.all())
            env.visible_folders = all_folders
            visible_environments.append(env)
            continue

        env_has_read_access = _has_access(user, "read", environment=env)
        if env_has_read_access:
            for folder in all_folders:
                folder.visible_secrets = list(folder.secrets.all())
            env.visible_folders = all_folders
            visible_environments.append(env)
            continue

        visible_folders = []
        for folder in all_folders:
            if _has_access(user, "read", folder=folder):
                folder.visible_secrets = list(folder.secrets.all())
                visible_folders.append(folder)
                continue

            readable_secrets = [secret for secret in folder.secrets.all() if _has_access(user, "read", secret=secret)]
            if readable_secrets:
                folder.visible_secrets = readable_secrets
                visible_folders.append(folder)

        if visible_folders:
            env.visible_folders = visible_folders
            visible_environments.append(env)

    return visible_environments


def _access_policy_sync_state():
    aggregate = AccessPolicy.objects.aggregate(last_updated_at=Max("updated_at"), rule_count=Count("id"))
    last_updated_at = aggregate.get("last_updated_at")
    rule_count = aggregate.get("rule_count") or 0
    token = f"{last_updated_at.isoformat() if last_updated_at else 'none'}:{rule_count}"
    return {
        "token": token,
        "last_updated_at": last_updated_at.isoformat() if last_updated_at else None,
        "rule_count": rule_count,
    }


@login_required
def dashboard(request):

    if "vault_key" not in request.session:
        return redirect("unseal")

    visibility_resolver = globals().get("_visible_environments_for_user")
    if callable(visibility_resolver):
        environments = visibility_resolver(request.user)
    else:
        logger.warning("Missing _visible_environments_for_user helper; using legacy environment visibility fallback.")
        if request.user.is_superuser:
            environments = Environment.objects.select_related("created_by").prefetch_related("folders__secrets").all()
            for env in environments:
                env.visible_folders = list(env.folders.all())
                for folder in env.visible_folders:
                    folder.visible_secrets = list(folder.secrets.all())
        else:
            readable_env_ids = AccessPolicy.objects.filter(
                user=request.user,
                can_read=True,
                environment__isnull=False,
            ).values_list("environment_id", flat=True)
            environments = Environment.objects.filter(
                Q(created_by=request.user) | Q(id__in=readable_env_ids)
            ).distinct().prefetch_related("folders__secrets")
            for env in environments:
                env.visible_folders = list(env.folders.all())
                for folder in env.visible_folders:
                    folder.visible_secrets = list(folder.secrets.all())
    environments = _visible_environments_for_user(request.user)
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
        env.can_read = _has_access(request.user, "read", environment=env)
        env.can_write = _has_access(request.user, "write", environment=env)
        env.can_delete = _has_access(request.user, "delete", environment=env)
        for folder in getattr(env, "visible_folders", []):
            folder.can_read = _has_access(request.user, "read", folder=folder)
            folder.can_write = _has_access(request.user, "write", folder=folder)
            folder.can_delete = _has_access(request.user, "delete", folder=folder)
            for secret in getattr(folder, "visible_secrets", []):
                secret.can_read = _has_access(request.user, "read", secret=secret)
                secret.can_write = _has_access(request.user, "write", secret=secret)
                secret.can_delete = _has_access(request.user, "delete", secret=secret)

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

    policy_sync_state = _access_policy_sync_state()
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
        "can_view_analysis": "analysis" in visible_feature_keys,
        "feature_rows": feature_rows,
        "setting_environments": _manageable_environments_for_settings(request.user).order_by("name"),
        "access_policy_sync_token": policy_sync_state["token"],
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
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    env = get_object_or_404(Environment, id=env_id)
    if not _has_access(request.user, "write", environment=env):
        if is_ajax:
            return JsonResponse({"ok": False, "error": "You do not have write access to this environment."}, status=403)
        return HttpResponseForbidden("You do not have write access to this environment.")

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        owner_email = (request.POST.get("owner_email") or "").strip()
        if not name:
            error_message = "Folder name is required."
            if is_ajax:
                return JsonResponse({"ok": False, "error": error_message}, status=400)
            messages.error(request, error_message)
            return redirect("vault_dashboard")

        folder = Folder.objects.create(name=name, owner_email=owner_email, environment=env)

        AuditLog.objects.create(
            user=request.user,
            action='CREATE',
            entity='Folder',
            details=f"Created folder '{name}' in environment '{env.name}'",
            ip_address=get_client_ip(request)
        )
        if is_ajax:
            return JsonResponse({
                "ok": True,
                "folder": {
                    "id": folder.id,
                    "name": folder.name,
                    "owner_email": folder.owner_email or "",
                }
            })

    if is_ajax:
        return JsonResponse({"ok": False, "error": "Invalid request method."}, status=405)
    return redirect("vault_dashboard")


# =========================
# CREATE SECRET
# =========================
@login_required
def add_secret(request, folder_id):
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    folder = get_object_or_404(Folder, id=folder_id)
    if not _has_access(request.user, "write", folder=folder):
        if is_ajax:
            return JsonResponse({"ok": False, "error": "You do not have write access to this folder."}, status=403)
        return HttpResponseForbidden("You do not have write access to this folder.")

    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        service_name = (request.POST.get("service_name") or "").strip()
        value = request.POST.get("value")
        expire = request.POST.get("expire")

        if not name:
            error_message = "Secret name is required."
            if is_ajax:
                return JsonResponse({"ok": False, "error": error_message}, status=400)
            messages.error(request, error_message)
            return redirect("vault_dashboard")
        if not value:
            error_message = "Secret value is required."
            if is_ajax:
                return JsonResponse({"ok": False, "error": error_message}, status=400)
            messages.error(request, error_message)
            return redirect("vault_dashboard")

        fallback_policy = SecretPolicy.objects.filter(created_by=request.user).first()
        env_policy = EnvironmentSecretPolicy.objects.filter(environment=folder.environment).first()
        policy = env_policy if (env_policy and env_policy.secret_value_regex) else fallback_policy
        regex_pattern = policy.secret_value_regex.strip() if policy else ""
        regex_mode = policy.regex_mode if policy else "match"

        if regex_pattern:
            try:
                is_match = bool(re.fullmatch(regex_pattern, value or ""))

                if regex_mode == "match" and not is_match:
                    error_message = "Secret should match the configured regex policy."
                    if is_ajax:
                        return JsonResponse({"ok": False, "error": error_message}, status=400)
                    messages.error(request, error_message)
                    return redirect("vault_dashboard")

                if regex_mode == "not_match" and is_match:
                    error_message = "Secret should not match the configured regex policy."
                    if is_ajax:
                        return JsonResponse({"ok": False, "error": error_message}, status=400)
                    messages.error(request, error_message)
                    return redirect("vault_dashboard")
            except re.error:
                error_message = "Configured regex policy is invalid. Please update Settings."
                if is_ajax:
                    return JsonResponse({"ok": False, "error": error_message}, status=400)
                messages.error(request, error_message)
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
        if is_ajax:
            return JsonResponse({
                "ok": True,
                "secret": {
                    "id": secret.id,
                    "name": secret.name,
                    "service_name": secret.service_name or "",
                    "expire_date": secret.expire_date.isoformat() if secret.expire_date else "",
                }
            })

    if is_ajax:
        return JsonResponse({"ok": False, "error": "Invalid request method."}, status=405)
    return redirect("vault_dashboard")


# =========================
# REVEAL SECRET
# =========================
@login_required
def reveal_secret(request, secret_id):
    secret = get_object_or_404(Secret, id=secret_id)
    if not _has_access(request.user, "read", secret=secret):
        return JsonResponse({"error": "You do not have read access for this secret."}, status=403)

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
@require_GET
def copy_secret(request, secret_id):
    secret = get_object_or_404(Secret, id=secret_id)
    if not _has_access(request.user, "read", secret=secret):
        return JsonResponse({"error": "You do not have read access for this secret."}, status=403)

    decrypted = decrypt_value(request, secret.encrypted_value)

    AuditLog.objects.create(
        user=request.user,
        action='COPY',
        entity='Secret',
        details=f"Copied secret '{secret.name}'",
        ip_address=get_client_ip(request)
    )

    return JsonResponse({"secret": decrypted})


@login_required
@require_GET
def copy_root_token(request):
    if not request.user.is_superuser:
        return JsonResponse({"error": "Only admin/root user can copy root token."}, status=403)

    root_token = request.session.get("vault_key")
    if not root_token:
        return JsonResponse({"error": "Vault root token is unavailable in this session."}, status=404)

    AuditLog.objects.create(
        user=request.user,
        action='ROOT_TOKEN_COPY',
        entity='Vault',
        details="Copied root token from dashboard",
        ip_address=get_client_ip(request)
    )

    return JsonResponse({"root_token": root_token})


def _within_search_rate_limit(user_id, limit=30, window_seconds=60, namespace="secret-path-search"):
    cache_key = f"{namespace}:{user_id}"
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

    if len(query) < 2:
        return JsonResponse({"error": "Enter at least 2 characters to search."}, status=400)
    if len(query) > 200:
        return JsonResponse({"error": "Search query is too long."}, status=400)

    search_scope = Secret.objects.select_related("folder", "folder__environment").filter(
        Q(name__icontains=query)
        | Q(service_name__icontains=query)
        | Q(folder__name__icontains=query)
        | Q(folder__environment__name__icontains=query)
    ).order_by("name")

    max_scan = 600
    scanned = 0
    matches = []
    for secret in search_scope[:max_scan]:
        scanned += 1
        if not _has_access(request.user, "read", secret=secret):
            continue

        matches.append({
            "secret_id": secret.id,
            "environment_id": secret.folder.environment_id,
            "folder_id": secret.folder_id,
            "environment": secret.folder.environment.name,
            "folder": secret.folder.name,
            "secret_name": secret.name,
            "service_name": secret.service_name,
            "path": f"{secret.folder.environment.name}/{secret.folder.name}/{secret.name}",
            "reveal_enabled": True,
        })
        if len(matches) >= 50:
            break

    AuditLog.objects.create(
        user=request.user,
        action="READ",
        entity="SecretSearch",
        details=f"Searched secret paths by metadata, query_len={len(query)}, results={len(matches)}",
        ip_address=get_client_ip(request),
    )

    return JsonResponse({
        "results": matches,
        "count": len(matches),
        "truncated": len(matches) >= 50 or scanned >= max_scan,
    })


@login_required
@require_GET
def search_expiring_secrets(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)

    if not _within_search_rate_limit(request.user.id, namespace="expiring-secret-search"):
        return JsonResponse({"error": "Too many requests. Please retry shortly."}, status=429)

    window = (request.GET.get("window") or "today").strip().lower()
    custom_date_raw = (request.GET.get("custom_date") or "").strip()

    today = timezone.now().date()
    if window == "today":
        target_date = today
        window_label = "Today"
    elif window == "3days":
        target_date = today + timedelta(days=3)
        window_label = "In 3 days"
    elif window == "5days":
        target_date = today + timedelta(days=5)
        window_label = "In 5 days"
    elif window == "custom":
        if not custom_date_raw:
            return JsonResponse({"error": "Please select a custom date."}, status=400)
        try:
            target_date = datetime.strptime(custom_date_raw, "%Y-%m-%d").date()
        except ValueError:
            return JsonResponse({"error": "Invalid custom date format. Use YYYY-MM-DD."}, status=400)
        window_label = f"Custom ({target_date.isoformat()})"
    else:
        return JsonResponse({"error": "Invalid expiration filter."}, status=400)

    search_scope = Secret.objects.select_related("folder", "folder__environment").filter(
        expire_date=target_date
    ).order_by("name")

    max_scan = 600
    scanned = 0
    matches = []
    for secret in search_scope[:max_scan]:
        scanned += 1
        if not _has_access(request.user, "read", secret=secret):
            continue

        matches.append({
            "secret_id": secret.id,
            "environment_id": secret.folder.environment_id,
            "folder_id": secret.folder_id,
            "environment": secret.folder.environment.name,
            "folder": secret.folder.name,
            "secret_name": secret.name,
            "service_name": secret.service_name,
            "path": f"{secret.folder.environment.name}/{secret.folder.name}/{secret.name}",
            "expire_date": secret.expire_date.isoformat() if secret.expire_date else "",
            "days_until_expiry": (secret.expire_date - today).days if secret.expire_date else None,
            "reveal_enabled": True,
        })
        if len(matches) >= 50:
            break

    AuditLog.objects.create(
        user=request.user,
        action="READ",
        entity="SecretExpirySearch",
        details=f"Searched expiring secrets, window={window}, target_date={target_date.isoformat()}, results={len(matches)}",
        ip_address=get_client_ip(request),
    )

    return JsonResponse({
        "results": matches,
        "count": len(matches),
        "window": window,
        "window_label": window_label,
        "target_date": target_date.isoformat(),
        "truncated": len(matches) >= 50 or scanned >= max_scan,
    })


@login_required
@require_GET
def run_vault_analysis(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    hours_raw = request.GET.get("hours", "24")
    try:
        hours = max(1, min(int(hours_raw), 24 * 30))
    except ValueError:
        return JsonResponse({"error": "Invalid analysis window."}, status=400)

    orchestrator = VaultAnalysisOrchestrator()
    payload = orchestrator.run(hours=hours)
    payload["delivery_plan"] = AlertingRouter().build_delivery_plan(payload.get("alert_groups", []))
    payload["analysis_window_hours"] = hours

    now = timezone.now()
    incidents = []
    for alert in payload.get("alert_groups", []):
        incident_key = f"{alert.get('username')}|{alert.get('action')}|{alert.get('entity')}"
        incident, _ = AnalysisIncident.objects.update_or_create(
            incident_key=incident_key,
            defaults={
                "username": alert.get("username", ""),
                "action": alert.get("action", ""),
                "entity": alert.get("entity", ""),
                "risk_score": int(alert.get("risk_score", 0)),
                "severity": alert.get("severity", "low"),
                "event_count": int(alert.get("event_count", 0)),
                "source_ip_count": int(alert.get("source_ip_count", 0)),
                "reasons": alert.get("reasons", []),
                "summary": " ".join(alert.get("reasons", []))[:500],
                "routing_status": ", ".join(payload.get("delivery_plan", [])),
                "first_seen_at": now,
                "last_seen_at": now,
            },
        )
        incidents.append(
            {
                "id": incident.id,
                "incident_key": incident.incident_key,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "assignee": incident.assignee.username if incident.assignee else "",
                "username": incident.username,
                "action": incident.action,
                "entity": incident.entity,
                "environment_label": incident.environment_label,
                "cluster_label": incident.cluster_label,
                "routing_status": incident.routing_status,
                "false_positive": incident.false_positive,
            }
        )

    payload["incidents"] = incidents
    payload["dedup_groups_count"] = len(payload.get("alert_groups", []))
    payload["baseline_comparison"] = payload.get("deviations", [])
    payload["trend_dashboard"] = payload.get("predictive_warnings", [])
    payload["audit_trail"] = list(
        AuditLog.objects.select_related("user")
        .filter(entity__in=["VaultAnalysis", "VaultAnalysisNLQ"])
        .order_by("-timestamp")
        .values("timestamp", "action", "entity", "details", "user__username")[:25]
    )

    AuditLog.objects.create(
        user=request.user,
        action="READ",
        entity="VaultAnalysis",
        details=f"Ran vault analysis (hours={hours}, alerts={len(payload.get('alert_groups', []))})",
        ip_address=get_client_ip(request),
    )
    return JsonResponse(payload)


@login_required
@require_GET
def query_vault_analysis(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    query_text = (request.GET.get("q") or "").strip()
    if not query_text:
        return JsonResponse({"error": "Query is empty."}, status=400)

    engine = AuditLogNLQueryEngine()
    result = engine.query(query_text, limit=120)
    if result.get("error"):
        return JsonResponse(result, status=400)

    AuditLog.objects.create(
        user=request.user,
        action="READ",
        entity="VaultAnalysisNLQ",
        details=f"Executed vault NL query (len={len(query_text)}, results={result.get('count', 0)})",
        ip_address=get_client_ip(request),
    )
    return JsonResponse(result)


@login_required
@require_GET
def list_analysis_incidents(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    queryset = AnalysisIncident.objects.select_related("assignee").all()
    severity = (request.GET.get("severity") or "").strip().lower()
    status = (request.GET.get("status") or "").strip().lower()
    if severity:
        queryset = queryset.filter(severity=severity)
    if status:
        queryset = queryset.filter(status=status)

    rows = []
    for incident in queryset[:200]:
        rows.append(
            {
                "id": incident.id,
                "incident_key": incident.incident_key,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "assignee": incident.assignee.username if incident.assignee else "",
                "username": incident.username,
                "action": incident.action,
                "entity": incident.entity,
                "environment_label": incident.environment_label,
                "cluster_label": incident.cluster_label,
                "routing_status": incident.routing_status,
                "false_positive": incident.false_positive,
            }
        )
    return JsonResponse({"incidents": rows, "count": len(rows)})


@login_required
@require_GET
def get_analysis_incident(request, incident_id):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    incident = get_object_or_404(AnalysisIncident.objects.select_related("assignee"), id=incident_id)
    timeline_rows = (
        AuditLog.objects.filter(user__username=incident.username, action=incident.action, entity=incident.entity)
        .extra(select={"hour": "strftime('%%Y-%%m-%%d %%H:00:00', timestamp)"})
        .values("hour")
        .annotate(count=Count("id"))
        .order_by("hour")[:48]
    )
    timeline = [{"hour": row["hour"], "count": row["count"]} for row in timeline_rows]
    identity_profile = {
        "username": incident.username,
        "open_incidents": AnalysisIncident.objects.filter(username=incident.username, status__in=["open", "investigating"]).count(),
        "avg_risk": AnalysisIncident.objects.filter(username=incident.username).aggregate(avg=Avg("risk_score")).get("avg") or 0,
    }
    secret_profile = {
        "entity": incident.entity,
        "action": incident.action,
        "incident_count": AnalysisIncident.objects.filter(entity=incident.entity, action=incident.action).count(),
    }

    return JsonResponse(
        {
            "incident": {
                "id": incident.id,
                "incident_key": incident.incident_key,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "assignee_id": incident.assignee_id,
                "assignee": incident.assignee.username if incident.assignee else "",
                "username": incident.username,
                "action": incident.action,
                "entity": incident.entity,
                "event_count": incident.event_count,
                "source_ip_count": incident.source_ip_count,
                "reasons": incident.reasons,
                "summary": incident.summary,
                "environment_label": incident.environment_label,
                "cluster_label": incident.cluster_label,
                "routing_status": incident.routing_status,
                "false_positive": incident.false_positive,
                "analyst_notes": incident.analyst_notes,
            },
            "timeline": timeline,
            "identity_profile": identity_profile,
            "secret_profile": secret_profile,
        }
    )


@login_required
def update_analysis_incident(request, incident_id):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    incident = get_object_or_404(AnalysisIncident, id=incident_id)
    status = (request.POST.get("status") or incident.status).strip().lower()
    assignee_id = (request.POST.get("assignee_id") or "").strip()
    notes = (request.POST.get("analyst_notes") or "").strip()
    false_positive = bool(request.POST.get("false_positive"))

    if status in {"open", "investigating", "resolved"}:
        incident.status = status
    incident.assignee = User.objects.filter(id=assignee_id).first() if assignee_id else None
    incident.analyst_notes = notes
    incident.false_positive = false_positive
    incident.save()

    AuditLog.objects.create(
        user=request.user,
        action="UPDATE",
        entity="VaultAnalysisIncident",
        details=f"Updated incident {incident.incident_key} status={incident.status} assignee={incident.assignee.username if incident.assignee else '-'} fp={incident.false_positive}",
        ip_address=get_client_ip(request),
    )
    return JsonResponse({"ok": True})


@login_required
def save_analysis_query(request):
    if request.method != "POST":
        return HttpResponseForbidden("Invalid request method")
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)

    name = (request.POST.get("name") or "").strip()
    query = (request.POST.get("query") or "").strip()
    if not name or not query:
        return JsonResponse({"error": "Name and query are required."}, status=400)
    item, _ = AnalysisSavedQuery.objects.update_or_create(
        user=request.user,
        name=name,
        defaults={"query": query},
    )
    return JsonResponse({"id": item.id, "name": item.name, "query": item.query})


@login_required
@require_GET
def list_analysis_queries(request):
    if "vault_key" not in request.session:
        return JsonResponse({"error": "Vault is sealed for this session."}, status=403)
    if not user_has_feature(request.user, "analysis"):
        return JsonResponse({"error": "You do not have vault analysis feature access."}, status=403)
    rows = list(
        AnalysisSavedQuery.objects.filter(user=request.user)
        .values("id", "name", "query")
        .order_by("name")
    )
    return JsonResponse({"saved_queries": rows, "count": len(rows)})


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


@login_required
def update_secret_value(request, secret_id):
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"

    if request.method != "POST":
        if is_ajax:
            return JsonResponse({"ok": False, "error": "Invalid request method."}, status=405)
        return HttpResponseForbidden("Invalid request method")

    secret = get_object_or_404(Secret, id=secret_id)
    if not _has_access(request.user, "write", secret=secret):
        if is_ajax:
            return JsonResponse({"ok": False, "error": "You do not have write access to this secret."}, status=403)
        return HttpResponseForbidden("You do not have write access to this secret.")

    new_value = request.POST.get("value")
    if not new_value:
        error_message = "Please provide a new secret value."
        if is_ajax:
            return JsonResponse({"ok": False, "error": error_message}, status=400)
        messages.error(request, error_message)
        return redirect("vault_dashboard")

    fallback_policy = SecretPolicy.objects.filter(created_by=request.user).first()
    env_policy = EnvironmentSecretPolicy.objects.filter(environment=secret.folder.environment).first()
    policy = env_policy if (env_policy and env_policy.secret_value_regex) else fallback_policy
    regex_pattern = policy.secret_value_regex.strip() if policy else ""
    regex_mode = policy.regex_mode if policy else "match"

    if regex_pattern:
        try:
            is_match = bool(re.fullmatch(regex_pattern, new_value))

            if regex_mode == "match" and not is_match:
                error_message = "Secret should match the configured regex policy."
                if is_ajax:
                    return JsonResponse({"ok": False, "error": error_message}, status=400)
                messages.error(request, error_message)
                return redirect("vault_dashboard")

            if regex_mode == "not_match" and is_match:
                error_message = "Secret should not match the configured regex policy."
                if is_ajax:
                    return JsonResponse({"ok": False, "error": error_message}, status=400)
                messages.error(request, error_message)
                return redirect("vault_dashboard")
        except re.error:
            error_message = "Configured regex policy is invalid. Please update Settings."
            if is_ajax:
                return JsonResponse({"ok": False, "error": error_message}, status=400)
            messages.error(request, error_message)
            return redirect("vault_dashboard")

    secret.encrypted_value = encrypt_value(request, new_value)
    secret.save(update_fields=["encrypted_value"])

    AuditLog.objects.create(
        user=request.user,
        action='UPDATE',
        entity='Secret',
        details=f"Updated value for secret '{secret.name}'",
        ip_address=get_client_ip(request)
    )
    success_message = f"Updated value for secret '{secret.name}'."
    if is_ajax:
        return JsonResponse({"ok": True, "message": success_message})
    messages.success(request, success_message)
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

    # Keep scope hierarchy consistent when narrower scope is provided.
    if secret:
        folder = secret.folder
        environment = secret.folder.environment
    elif folder and not environment:
        environment = folder.environment

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
        parsed = _parse_policy_document(raw, doc_format)
        updated, skipped = _apply_access_policy_rules(parsed)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("vault_dashboard")

    messages.success(request, f"Policy document processed. Updated {updated} rule(s), skipped {skipped}.")
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


def _load_rsa_public_key_from_pem():
    pem_path = getattr(settings, "JWKS_PUBLIC_KEY_PATH", None)
    if not pem_path:
        raise ValueError("JWKS_PUBLIC_KEY_PATH setting is not configured.")
    with open(pem_path, "rb") as pem_file:
        loaded_key = serialization.load_pem_public_key(pem_file.read())
    if not isinstance(loaded_key, rsa.RSAPublicKey):
        raise ValueError("Configured PEM key is not an RSA public key.")
    return loaded_key


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


def _parse_policy_document(raw_document, document_format):
    if document_format not in {"json", "yaml"}:
        raise ValueError("document_format must be either 'json' or 'yaml'.")

    try:
        parsed = json.loads(raw_document) if document_format == "json" else yaml.safe_load(raw_document)
    except Exception as exc:
        raise ValueError(f"Invalid {document_format.upper()} policy document: {exc}") from exc

    rules = parsed.get("rules") if isinstance(parsed, dict) else None
    if not isinstance(rules, list):
        raise ValueError("Policy document must contain a top-level 'rules' list.")

    return rules


def _apply_access_policy_rules(rules):
    updated = 0
    skipped = 0
    for rule in rules:
        username = (rule.get("user") or "").strip()
        if not username:
            skipped += 1
            continue
        target_user = User.objects.filter(username__iexact=username).first()
        if not target_user:
            skipped += 1
            continue

        environment_name = (rule.get("environment") or "").strip()
        folder_name = (rule.get("folder") or "").strip()
        secret_name = (rule.get("secret") or "").strip()

        environment = None
        if environment_name:
            environment_matches = Environment.objects.filter(name__iexact=environment_name)
            if environment_matches.count() != 1:
                skipped += 1
            environment_matches = Environment.objects.filter(name=environment_name)
            if environment_matches.count() != 1:
                continue
            environment = environment_matches.first()

        folder = None
        if folder_name:
            folder_matches = Folder.objects.filter(name__iexact=folder_name)
            if environment:
                folder_matches = folder_matches.filter(environment=environment)
            if folder_matches.count() != 1:
                skipped += 1
            folder_matches = Folder.objects.filter(name=folder_name)
            if environment:
                folder_matches = folder_matches.filter(environment=environment)
            if folder_matches.count() != 1:
                continue
            folder = folder_matches.first()

        secret = None
        if secret_name:
            secret_matches = Secret.objects.filter(name__iexact=secret_name)
            secret_matches = Secret.objects.filter(name=secret_name)
            if folder:
                secret_matches = secret_matches.filter(folder=folder)
            elif environment:
                secret_matches = secret_matches.filter(folder__environment=environment)
            if secret_matches.count() != 1:
                skipped += 1
                continue
            secret = secret_matches.first()

        permissions = rule.get("permissions") or {}
        AccessPolicy.objects.update_or_create(
            user=target_user,
            environment=environment,
            folder=folder,
            secret=secret,
            defaults={
                "can_read": bool(permissions.get("read")),
                "can_write": bool(permissions.get("write")),
                "can_delete": bool(permissions.get("delete")),
            },
        )
        updated += 1

    return updated, skipped


@csrf_exempt
@login_required
@require_GET
def cli_ping(request):
    return JsonResponse(
        {
            "ok": True,
            "vault": "civault",
            "user": request.user.username,
            "is_superuser": request.user.is_superuser,
        }
    )


@csrf_exempt
@login_required
@require_GET
def cli_list_secrets(request):
    environment_name = (request.GET.get("environment") or "").strip()
    folder_name = (request.GET.get("folder") or "").strip()
    show_values = str(request.GET.get("show_values") or "").lower() in {"1", "true", "yes"}

    if not environment_name or not folder_name:
        return JsonResponse({"ok": False, "error": "Both 'environment' and 'folder' are required."}, status=400)

    environment = Environment.objects.filter(name=environment_name).first()
    if not environment:
        return JsonResponse({"ok": False, "error": f"Environment '{environment_name}' not found."}, status=404)

    folder = Folder.objects.filter(name=folder_name, environment=environment).first()
    if not folder:
        return JsonResponse({"ok": False, "error": f"Folder '{folder_name}' not found in '{environment_name}'."}, status=404)

    if not _has_access(request.user, "read", folder=folder):
        return JsonResponse({"ok": False, "error": "You do not have read access to this folder."}, status=403)

    rows = []
    for secret in Secret.objects.filter(folder=folder).order_by("id"):
        item = {
            "id": secret.id,
            "name": secret.name,
            "service_name": secret.service_name or "",
            "expire_date": secret.expire_date.isoformat() if secret.expire_date else None,
        }
        if show_values:
            try:
                item["value"] = decrypt_value(request, secret.encrypted_value)
            except Exception:
                item["value"] = None
        rows.append(item)

    AuditLog.objects.create(
        user=request.user,
        action="REVEAL" if show_values else "COPY",
        entity="Secret",
        details=(
            f"[CLI] Listed {len(rows)} secret(s) in '{environment_name}/{folder_name}' "
            f"(show_values={'yes' if show_values else 'no'})"
        ),
        ip_address=get_client_ip(request),
    )

    return JsonResponse(
        {
            "ok": True,
            "vault": "civault",
            "environment": environment_name,
            "folder": folder_name,
            "count": len(rows),
            "secrets": rows,
        }
    )


@csrf_exempt
@login_required
def cli_add_secret(request):
    if request.method != "POST":
        return JsonResponse({"ok": False, "error": "POST method required."}, status=405)

    payload = {}
    if request.content_type and "application/json" in request.content_type:
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return JsonResponse({"ok": False, "error": "Invalid JSON body."}, status=400)
    else:
        payload = request.POST

    environment_name = (payload.get("environment") or "").strip()
    folder_name = (payload.get("folder") or "").strip()
    name = (payload.get("name") or "").strip()
    value = payload.get("value")
    service_name = (payload.get("service_name") or "").strip()
    expire_raw = (payload.get("expire_date") or "").strip()

    if not environment_name or not folder_name or not name or not value:
        return JsonResponse(
            {"ok": False, "error": "environment, folder, name and value are required."},
            status=400,
        )

    environment = Environment.objects.filter(name=environment_name).first()
    if not environment:
        return JsonResponse({"ok": False, "error": f"Environment '{environment_name}' not found."}, status=404)

    folder = Folder.objects.filter(name=folder_name, environment=environment).first()
    if not folder:
        return JsonResponse({"ok": False, "error": f"Folder '{folder_name}' not found in '{environment_name}'."}, status=404)

    if not _has_access(request.user, "write", folder=folder):
        return JsonResponse({"ok": False, "error": "You do not have write access to this folder."}, status=403)

    expire_date = None
    if expire_raw:
        try:
            expire_date = datetime.strptime(expire_raw, "%Y-%m-%d").date()
        except ValueError:
            return JsonResponse({"ok": False, "error": "expire_date must be in YYYY-MM-DD format."}, status=400)

    secret = Secret.objects.create(
        name=name,
        service_name=service_name,
        encrypted_value=encrypt_value(request, value),
        expire_date=expire_date,
        folder=folder,
    )
    AuditLog.objects.create(
        user=request.user,
        action="CREATE",
        entity="Secret",
        details=f"[CLI] Created secret '{name}' in folder '{folder.name}'",
        ip_address=get_client_ip(request),
    )

    return JsonResponse(
        {
            "ok": True,
            "vault": "civault",
            "secret": {
                "id": secret.id,
                "name": secret.name,
                "service_name": secret.service_name or "",
                "expire_date": secret.expire_date.isoformat() if secret.expire_date else None,
            },
        },
        status=201,
    )


@csrf_exempt
@login_required
def cli_delete_secret(request):
    if request.method != "POST":
        return JsonResponse({"ok": False, "error": "POST method required."}, status=405)

    payload = {}
    if request.content_type and "application/json" in request.content_type:
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return JsonResponse({"ok": False, "error": "Invalid JSON body."}, status=400)
    else:
        payload = request.POST

    environment_name = (payload.get("environment") or "").strip()
    folder_name = (payload.get("folder") or "").strip()
    secret_id = payload.get("id")
    secret_name = (payload.get("name") or "").strip()

    if not environment_name or not folder_name:
        return JsonResponse({"ok": False, "error": "environment and folder are required."}, status=400)
    if secret_id in (None, "") and not secret_name:
        return JsonResponse({"ok": False, "error": "Provide either id or name to delete a secret."}, status=400)

    environment = Environment.objects.filter(name=environment_name).first()
    if not environment:
        return JsonResponse({"ok": False, "error": f"Environment '{environment_name}' not found."}, status=404)

    folder = Folder.objects.filter(name=folder_name, environment=environment).first()
    if not folder:
        return JsonResponse({"ok": False, "error": f"Folder '{folder_name}' not found in '{environment_name}'."}, status=404)

    if not _has_access(request.user, "delete", folder=folder):
        return JsonResponse({"ok": False, "error": "You do not have delete access to this folder."}, status=403)

    secrets = Secret.objects.filter(folder=folder)
    if secret_id not in (None, ""):
        try:
            secrets = secrets.filter(id=int(secret_id))
        except ValueError:
            return JsonResponse({"ok": False, "error": "id must be an integer."}, status=400)
    else:
        secrets = secrets.filter(name=secret_name)

    secret = secrets.first()
    if not secret:
        return JsonResponse({"ok": False, "error": "Secret not found in the requested scope."}, status=404)

    deleted = {"id": secret.id, "name": secret.name}
    secret.delete()
    AuditLog.objects.create(
        user=request.user,
        action="DELETE",
        entity="Secret",
        details=f"[CLI] Deleted secret '{deleted['name']}' from folder '{folder.name}'",
        ip_address=get_client_ip(request),
    )

    return JsonResponse({"ok": True, "vault": "civault", "deleted": deleted})


@csrf_exempt
@login_required
@require_POST
def cli_apply_policy(request):
    if not user_has_feature(request.user, "policy"):
        return JsonResponse({"ok": False, "error": "You do not have policy engine feature access."}, status=403)

    payload = {}
    if request.content_type and "application/json" in request.content_type:
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return JsonResponse({"ok": False, "error": "Invalid JSON body."}, status=400)
    else:
        payload = request.POST

    raw = (payload.get("policy_document") or "").strip()
    doc_format = (payload.get("document_format") or "json").strip().lower()
    if not raw:
        return JsonResponse({"ok": False, "error": "policy_document is required."}, status=400)

    try:
        rules = _parse_policy_document(raw, doc_format)
        updated, skipped = _apply_access_policy_rules(rules)
    except ValueError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    AuditLog.objects.create(
        user=request.user,
        action="UPDATE",
        entity="AccessPolicy",
        details=f"[CLI] Applied policy document. Updated {updated} rule(s), skipped {skipped}.",
        ip_address=get_client_ip(request),
    )

    return JsonResponse({"ok": True, "vault": "civault", "updated_rules": updated, "skipped_rules": skipped})


@csrf_exempt
@login_required
@require_GET
def cli_policy_sync_state(request):
    sync_state = _access_policy_sync_state()
    return JsonResponse(
        {
            "ok": True,
            "vault": "civault",
            "policy_sync_token": sync_state["token"],
            "rule_count": sync_state["rule_count"],
            "last_updated_at": sync_state["last_updated_at"],
        }
    )


@csrf_exempt
@login_required
@require_GET
def cli_policy_sync_state(request):
    sync_state = _access_policy_sync_state()
    return JsonResponse(
        {
            "ok": True,
            "vault": "civault",
            "policy_sync_token": sync_state["token"],
            "rule_count": sync_state["rule_count"],
            "last_updated_at": sync_state["last_updated_at"],
        }
    )


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
    algorithm = str(unverified_header.get("alg") or "").strip()
    kid = unverified_header.get("kid")

    logger.info(
        "JWT machine login attempt: iss=%s aud=%s sub=%s kid=%s alg=%s identity_name=%s",
        issuer,
        audiences,
        subject,
        kid,
        algorithm,
        identity_name or None,
    )

    if not issuer:
        return JsonResponse({"error": "JWT 'iss' claim is required."}, status=400)
    if not audiences:
        return JsonResponse({"error": "JWT 'aud' claim is required."}, status=400)
    if not subject:
        return JsonResponse({"error": "JWT 'sub' claim is required."}, status=400)
    if algorithm != "RS256":
        return JsonResponse({"error": f"Unsupported JWT algorithm '{algorithm}'. Expected 'RS256'."}, status=400)

    identities = JWTWorkloadIdentity.objects.select_related("machine_policy", "machine_policy__access_policy").filter(
        issuer=issuer,
        audience__in=audiences,
        is_active=True,
    )
    if identity_name:
        identities = identities.filter(name=identity_name)
    identities = list(identities)
    if not identities:
        logger.warning(
            "JWT machine login rejected: no matching active identity for iss=%s aud=%s identity_name=%s",
            issuer,
            audiences,
            identity_name or None,
        )
        return JsonResponse({"error": "No active JWT workload identity matches this token."}, status=403)

    verified_identity = None
    verified_claims = None
    verification_errors = []
    for identity in identities:
        if identity.subject_pattern and not fnmatch(subject, identity.subject_pattern):
            reason = (
                f"identity '{identity.name}' skipped: subject '{subject}' does not match "
                f"pattern '{identity.subject_pattern}'."
            )
            logger.info("JWT verify detail: %s", reason)
            verification_errors.append(reason)
            continue

        resolved_jwks_url = (identity.jwks_url or "").strip()
        if resolved_jwks_url and resolved_jwks_url.startswith("/"):
            resolved_jwks_url = request.build_absolute_uri(resolved_jwks_url)

        try:
            if resolved_jwks_url:
                key = _get_signing_key_from_jwks(resolved_jwks_url, kid)
            else:
                key = _load_rsa_public_key_from_pem()

            verified = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=identity.audience,
                issuer=identity.issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except FileNotFoundError:
            reason = (
                f"identity '{identity.name}' failed: JWKS_PUBLIC_KEY_PATH file not found "
                "for PEM fallback verification."
            )
            logger.warning("JWT verify detail: %s", reason)
            verification_errors.append(reason)
            continue
        except requests.RequestException as exc:
            reason = f"identity '{identity.name}' failed: unable to fetch JWKS ({exc})."
            logger.warning("JWT verify detail: %s", reason)
            verification_errors.append(reason)
            continue
        except ValueError as exc:
            reason = f"identity '{identity.name}' failed: {exc}."
            logger.warning("JWT verify detail: %s", reason)
            verification_errors.append(reason)
            continue
        except InvalidTokenError as exc:
            reason = f"identity '{identity.name}' failed: token validation error ({exc})."
            logger.info("JWT verify detail: %s", reason)
            verification_errors.append(reason)
            continue
        verified_identity = identity
        verified_claims = verified
        logger.info(
            "JWT machine login verified with identity=%s policy=%s subject=%s",
            identity.name,
            identity.machine_policy.name,
            verified_claims.get("sub"),
        )
        break

    if not verified_identity:
        logger.warning(
            "JWT machine login failed for iss=%s aud=%s sub=%s. details=%s",
            issuer,
            audiences,
            subject,
            verification_errors,
        )
        return JsonResponse(
            {
                "error": "JWT verification failed for all matching identities.",
                "details": verification_errors or ["No identity was able to verify this JWT."],
            },
            status=403,
        )

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

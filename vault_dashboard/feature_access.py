from .models import UserFeatureAccess


FEATURE_CATALOG = [
    {"key": "secrets", "label": "Secrets Manager", "default_enabled": True},
    {"key": "settings", "label": "Settings", "default_enabled": False},
    {"key": "policy", "label": "Policy Engine", "default_enabled": False},
    {"key": "approvals", "label": "Approvals", "default_enabled": False},
    {"key": "notifications", "label": "Notifications", "default_enabled": False},
    {"key": "audit_logs", "label": "Audit Logs", "default_enabled": False},
    {"key": "seal_vault", "label": "Seal Vault", "default_enabled": False},
    {"key": "analysis", "label": "Vault Analysis", "default_enabled": False},
]
FEATURE_DEFAULTS = {item["key"]: item["default_enabled"] for item in FEATURE_CATALOG}


def resolve_user_feature_visibility(user):
    if user.is_superuser:
        return {item["key"] for item in FEATURE_CATALOG}

    rules = {
        row.feature_key: row.can_view
        for row in UserFeatureAccess.objects.filter(user=user)
    }

    visible = set()
    for feature in FEATURE_CATALOG:
        key = feature["key"]
        default_enabled = FEATURE_DEFAULTS.get(key, False)
        if rules.get(key, default_enabled):
            visible.add(key)
    return visible


def user_has_feature(user, feature_key):
    if user.is_superuser:
        return True
    return feature_key in resolve_user_feature_visibility(user)

from datetime import timedelta

from django.utils import timezone

from auditlogs.models import AuditLog


class AuditLogIngestionService:
    """Loads audit logs and strips sensitive payloads for analytics use."""

    def load(self, hours=24, limit=2000):
        since = timezone.now() - timedelta(hours=max(int(hours), 1))
        rows = (
            AuditLog.objects.select_related("user")
            .filter(timestamp__gte=since)
            .order_by("-timestamp")[:limit]
        )
        sanitized = []
        for row in rows:
            sanitized.append(
                {
                    "id": row.id,
                    "timestamp": row.timestamp,
                    "user_id": row.user_id,
                    "username": row.user.username,
                    "action": row.action,
                    "entity": row.entity,
                    "ip_address": row.ip_address or "",
                    # Intentionally omit raw `details` from analytics output.
                }
            )
        return sanitized

from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from auditlogs.models import AuditLog


class AuditLogNLQueryEngine:
    """
    Rule-based NL query interpreter for V1.
    Keeps responses explainable and deterministic.
    """

    def query(self, text, limit=100):
        q = (text or "").strip().lower()
        if not q:
            return {"error": "Query is empty."}

        queryset = AuditLog.objects.select_related("user").order_by("-timestamp")
        timeframe = None
        if "today" in q:
            timeframe = timezone.now() - timedelta(days=1)
        elif "week" in q:
            timeframe = timezone.now() - timedelta(days=7)
        if timeframe:
            queryset = queryset.filter(timestamp__gte=timeframe)

        explanation = "General audit log search."
        if q.startswith("who accessed"):
            queryset = queryset.filter(Q(action="REVEAL") | Q(action="COPY"))
            explanation = "Matched query intent: who accessed what."
        elif "policy" in q:
            queryset = queryset.filter(entity__icontains="policy")
            explanation = "Matched policy-related investigation."
        elif "failed" in q or "denied" in q:
            queryset = queryset.filter(details__iregex=r"(failed|denied|forbidden)")
            explanation = "Matched failure/denial investigation."
        elif "session" in q:
            queryset = queryset.filter(Q(action="LOGIN") | Q(action="LOGOUT"))
            explanation = "Matched session reconstruction intent."
        else:
            queryset = queryset.filter(
                Q(entity__icontains=q) | Q(action__icontains=q) | Q(user__username__icontains=q)
            )
            explanation = "Matched free-text entity/action/user search."

        rows = []
        for row in queryset[:limit]:
            rows.append(
                {
                    "id": row.id,
                    "timestamp": row.timestamp.isoformat(),
                    "user": row.user.username,
                    "action": row.action,
                    "entity": row.entity,
                    "ip_address": row.ip_address,
                }
            )
        return {"explanation": explanation, "results": rows, "count": len(rows)}

from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from .models import AuditLog
from vault_dashboard.feature_access import user_has_feature


@login_required
def audit_dashboard(request):
    if not user_has_feature(request.user, "audit_logs"):
        return HttpResponseForbidden("You do not have audit logs feature access.")

    logs = AuditLog.objects.all().order_by('-timestamp')[:200]

    return render(request, "auditlogs/dashboard.html", {
        "logs": logs
    })

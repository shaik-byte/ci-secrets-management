from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from .models import AuditLog


@login_required
def audit_dashboard(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("Only admin can access audit logs.")

    logs = AuditLog.objects.all().order_by('-timestamp')[:200]

    return render(request, "auditlogs/dashboard.html", {
        "logs": logs
    })

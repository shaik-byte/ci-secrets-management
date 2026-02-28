from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import AuditLog


@login_required
def audit_dashboard(request):
    logs = AuditLog.objects.all().order_by('-timestamp')[:200]

    return render(request, "auditlogs/dashboard.html", {
        "logs": logs
    })
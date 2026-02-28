from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import EmailConfig


@login_required
def notification_dashboard(request):

    config = EmailConfig.objects.filter(created_by=request.user).first()

    return render(request, "notifications/dashboard.html", {
        "config": config
    })


@login_required
def save_notification_config(request):

    if request.method == "POST":

        config, created = EmailConfig.objects.get_or_create(
            created_by=request.user
        )

        config.from_email = request.POST.get("from_email")
        config.to_email = request.POST.get("to_email")
        config.cc_email = request.POST.get("cc_email")
        config.bcc_email = request.POST.get("bcc_email")
        config.app_password = request.POST.get("app_password")

        config.save()

    return redirect("notifications")
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from .models import EmailConfig
from vault_dashboard.feature_access import user_has_feature


@login_required
def notification_dashboard(request):
    if not user_has_feature(request.user, "notifications"):
        return HttpResponseForbidden("You do not have notifications feature access.")

    config = EmailConfig.objects.filter(created_by=request.user).first()

    return render(
        request,
        "notifications/dashboard.html",
        {
            "config": config,
            "has_app_password": bool(config and config.has_app_password),
            "has_google_chat_webhook": bool(config and config.has_google_chat_webhook),
            "has_microsoft_teams_webhook": bool(config and config.has_microsoft_teams_webhook),
            "has_slack_webhook": bool(config and config.has_slack_webhook),
        },
    )


@login_required
def save_notification_config(request):
    if not user_has_feature(request.user, "notifications"):
        return HttpResponseForbidden("You do not have notifications feature access.")

    if request.method == "POST":
        config, _ = EmailConfig.objects.get_or_create(created_by=request.user)

        config.from_email = request.POST.get("from_email")
        config.to_email = request.POST.get("to_email")
        config.cc_email = request.POST.get("cc_email")
        config.bcc_email = request.POST.get("bcc_email")

        submitted_app_password = (request.POST.get("app_password") or "").strip()
        if submitted_app_password:
            config.set_app_password(submitted_app_password)

        submitted_google_chat_webhook = (request.POST.get("google_chat_webhook") or "").strip()
        if submitted_google_chat_webhook:
            config.set_google_chat_webhook(submitted_google_chat_webhook)

        submitted_microsoft_teams_webhook = (request.POST.get("microsoft_teams_webhook") or "").strip()
        if submitted_microsoft_teams_webhook:
            config.set_microsoft_teams_webhook(submitted_microsoft_teams_webhook)
        config.microsoft_teams_channel = (request.POST.get("microsoft_teams_channel") or "").strip()

        submitted_slack_webhook = (request.POST.get("slack_webhook") or "").strip()
        if submitted_slack_webhook:
            config.set_slack_webhook(submitted_slack_webhook)
        config.slack_channel = (request.POST.get("slack_channel") or "").strip()

        config.save()

    return redirect("notifications")

import smtplib
import json
from urllib import error, request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .models import EmailConfig


def send_expiry_email(user, secret):
    config = EmailConfig.objects.filter(created_by=user).first()
    if not config:
        return False

    app_password = config.get_app_password()
    if not app_password:
        return False

    msg = MIMEMultipart()
    msg['From'] = config.from_email
    msg['To'] = config.to_email
    msg['Cc'] = config.cc_email if config.cc_email else ""
    msg['Subject'] = f"Secret Expiry Alert: {secret.name}"

    body = f"""
    🚨 SECRET EXPIRY ALERT 🚨

    Environment : {secret.folder.environment.name}
    Folder      : {secret.folder.name}
    Secret Name : {secret.name}
    Expiry Date : {secret.expire_date}

    This secret is scheduled to expire soon.
    Please rotate or update it immediately.

    -- Automated Vault Notification System
    """
    msg.attach(MIMEText(body, 'plain'))

    recipients = (
        config.to_email.split(",")
        + (config.cc_email.split(",") if config.cc_email else [])
        + (config.bcc_email.split(",") if config.bcc_email else [])
    )

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(config.from_email, app_password)
    server.sendmail(config.from_email, recipients, msg.as_string())
    server.quit()
    return True


def send_expiry_google_chat_message(user, secret):
    config = EmailConfig.objects.filter(created_by=user).first()
    if not config or not config.has_google_chat_webhook:
        return False

    webhook_url = config.get_google_chat_webhook()
    payload = {
        "text": (
            "🚨 *Secret Expiry Alert* 🚨\n"
            f"Environment: {secret.folder.environment.name}\n"
            f"Folder: {secret.folder.name}\n"
            f"Secret: {secret.name}\n"
            f"Expiry Date: {secret.expire_date}\n"
            "Please rotate or update it immediately."
        )
    }

    req = request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=UTF-8"},
        method="POST",
    )
    try:
        request.urlopen(req, timeout=10)
    except error.URLError as exc:
        raise RuntimeError(f"Google Chat notification failed: {exc}") from exc
    return True

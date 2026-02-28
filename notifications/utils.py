import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .models import EmailConfig


def send_expiry_email(user, secret):

    config = EmailConfig.objects.filter(created_by=user).first()
    if not config:
        return

    msg = MIMEMultipart()
    msg['From'] = config.from_email
    msg['To'] = config.to_email
    msg['Cc'] = config.cc_email if config.cc_email else ""
    msg['Subject'] = f"Secret Expiry Alert: {secret.name}"

    # body = f"""
    # Secret '{secret.name}' is expiring on {secret.expire_date}.
    # Please rotate or update it immediately.
    # """
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
        config.to_email.split(",") +
        (config.cc_email.split(",") if config.cc_email else []) +
        (config.bcc_email.split(",") if config.bcc_email else [])
    )

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(config.from_email, config.app_password)
    server.sendmail(config.from_email, recipients, msg.as_string())
    server.quit()
from apscheduler.schedulers.background import BackgroundScheduler
from django.utils import timezone
from datetime import timedelta
from vault_dashboard.models import Secret
from notifications.utils import send_expiry_email
import logging

logger = logging.getLogger(__name__)

def check_expiry_job():
    today = timezone.now().date()
    upcoming = today + timedelta(days=1)

    secrets = Secret.objects.filter(
        expire_date__isnull=False,
        expire_date__lte=upcoming,
        notified=False
    )

    for secret in secrets:
        try:
            user = secret.folder.environment.created_by
            send_expiry_email(user, secret)

            secret.notified = True
            secret.save()

            logger.info(f"Notification sent for {secret.name}")

        except Exception as e:
            logger.error(f"Failed sending notification for {secret.name}: {e}")

# def start_scheduler():
#     scheduler = BackgroundScheduler()
#     scheduler.add_job(
#         check_expiry_job,
#         'interval',
#         minutes=30,
#         id='expiry_checker',
#         replace_existing=True
#     )
#     scheduler.start()

import os

def start_scheduler():
    if os.environ.get('RUN_MAIN') != 'true':
        return

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        check_expiry_job,
        'interval',
        minutes=2,
        id='expiry_checker',
        replace_existing=True
    )
    scheduler.start()
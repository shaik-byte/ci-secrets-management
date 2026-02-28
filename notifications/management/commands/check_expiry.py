from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from vault_dashboard.models import Secret
from notifications.utils import send_expiry_email


class Command(BaseCommand):
    help = "Check expiring secrets and send notifications"

    def handle(self, *args, **kwargs):

        today = timezone.now().date()
        upcoming = today + timedelta(days=1)  # Notify 1 day before expiry

        secrets = Secret.objects.filter(
            expire_date__isnull=False,
            expire_date__lte=upcoming,
            notified=False
        )

        if not secrets.exists():
            self.stdout.write("No expiring secrets found.")
            return

        for secret in secrets:
            user = secret.folder.environment.created_by

            try:
                send_expiry_email(user, secret)
                secret.notified = True
                secret.save()

                self.stdout.write(
                    self.style.SUCCESS(f"Notification sent for: {secret.name}")
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed for {secret.name}: {str(e)}")
                )
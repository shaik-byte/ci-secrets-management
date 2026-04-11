from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from vault_dashboard.models import Secret
from notifications.utils import send_expiry_email, send_expiry_google_chat_message


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
                email_sent = send_expiry_email(user, secret)
                chat_sent = send_expiry_google_chat_message(user, secret)

                if email_sent or chat_sent:
                    secret.notified = True
                    secret.save()

                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Notification sent for: {secret.name} "
                            f"(email={'yes' if email_sent else 'no'}, chat={'yes' if chat_sent else 'no'})"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f"No notification channels configured for: {secret.name}"
                        )
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Failed for {secret.name}: {str(e)}")
                )

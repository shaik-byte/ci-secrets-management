from django.contrib.auth.models import User
from django.db import models

from .crypto_utils import decrypt_notification_secret, encrypt_notification_secret


class EmailConfig(models.Model):
    created_by = models.OneToOneField(User, on_delete=models.CASCADE)

    from_email = models.EmailField()
    notified = models.BooleanField(default=False)
    to_email = models.TextField(help_text="Comma separated emails")
    cc_email = models.TextField(blank=True, null=True)
    bcc_email = models.TextField(blank=True, null=True)

    app_password_encrypted = models.BinaryField(null=True, blank=True)
    google_chat_webhook_encrypted = models.BinaryField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def set_app_password(self, plain_password: str) -> None:
        self.app_password_encrypted = encrypt_notification_secret(plain_password)

    def get_app_password(self) -> str:
        return decrypt_notification_secret(self.app_password_encrypted)

    def set_google_chat_webhook(self, webhook_url: str) -> None:
        self.google_chat_webhook_encrypted = encrypt_notification_secret(webhook_url)

    def get_google_chat_webhook(self) -> str:
        return decrypt_notification_secret(self.google_chat_webhook_encrypted)

    @property
    def has_app_password(self) -> bool:
        return bool(self.app_password_encrypted)

    @property
    def has_google_chat_webhook(self) -> bool:
        return bool(self.google_chat_webhook_encrypted)

    def __str__(self):
        return f"Email Config - {self.created_by.username}"

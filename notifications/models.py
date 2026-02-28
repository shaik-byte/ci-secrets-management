from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User


class EmailConfig(models.Model):
    created_by = models.OneToOneField(User, on_delete=models.CASCADE)

    from_email = models.EmailField()
    notified = models.BooleanField(default=False)
    to_email = models.TextField(help_text="Comma separated emails")
    cc_email = models.TextField(blank=True, null=True)
    bcc_email = models.TextField(blank=True, null=True)

    app_password = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Email Config - {self.created_by.username}"
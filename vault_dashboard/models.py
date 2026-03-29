from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User


class Environment(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Folder(models.Model):
    name = models.CharField(max_length=255)
    environment = models.ForeignKey(Environment, on_delete=models.CASCADE, related_name="folders")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.environment.name} / {self.name}"


class Secret(models.Model):
    name = models.CharField(max_length=255)
    service_name = models.CharField(max_length=255, blank=True, default="")
    owner_email = models.EmailField(blank=True, default="")
    encrypted_value = models.BinaryField()
    notified = models.BooleanField(default=False)
    is_access_enabled = models.BooleanField(default=False)
    expire_date = models.DateField(null=True, blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name="secrets")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class SecretPolicy(models.Model):
    MATCH_MODE_CHOICES = [
        ("match", "Should Match"),
        ("not_match", "Should Not Match"),
    ]

    created_by = models.OneToOneField(User, on_delete=models.CASCADE)
    secret_value_regex = models.CharField(max_length=500, blank=True, default="")
    regex_mode = models.CharField(max_length=20, choices=MATCH_MODE_CHOICES, default="match")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Secret Policy - {self.created_by.username}"


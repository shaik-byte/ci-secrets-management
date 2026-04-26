from django.db import models
from django.utils import timezone


class Secret(models.Model):
    name = models.CharField(max_length=255)
    encrypted_value = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)


class VaultConfig(models.Model):
    encrypted_root_key = models.BinaryField()
    allowed_location = models.CharField(max_length=255)
    initialized = models.BooleanField(default=False)
    sealed = models.BooleanField(default=True)
    total_shares = models.IntegerField(default=5)
    threshold = models.IntegerField(default=3)
    root_token_hash = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    initialized_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_sealed(self):
        return self.sealed

    @is_sealed.setter
    def is_sealed(self, value):
        self.sealed = value

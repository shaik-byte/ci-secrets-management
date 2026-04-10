from django.db import models


class Secret(models.Model):
    name = models.CharField(max_length=255)
    encrypted_value = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)


class VaultConfig(models.Model):
    encrypted_root_key = models.BinaryField()
    allowed_location = models.CharField(max_length=255)
    is_sealed = models.BooleanField(default=True)
    total_shares = models.IntegerField(default=5)
    threshold = models.IntegerField(default=3)

from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

# class VaultConfig(models.Model):
#     is_sealed = models.BooleanField(default=True)
#     encrypted_root_key = models.BinaryField()
#     device_id = models.CharField(max_length=255)
#     allowed_location = models.CharField(max_length=255)
#     created_at = models.DateTimeField(auto_now_add=True)

# class VaultConfig(models.Model):
#     is_sealed = models.BooleanField(default=True)
#     encrypted_root_key = models.BinaryField()

#     total_shares = models.IntegerField(default=5)
#     threshold = models.IntegerField(default=3)

#     device_id = models.CharField(max_length=255)
#     allowed_location = models.CharField(max_length=255)

#     created_at = models.DateTimeField(auto_now_add=True)

class Secret(models.Model):
    name = models.CharField(max_length=255)
    encrypted_value = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)


# class VaultConfig(models.Model):
#     encrypted_root_key = models.BinaryField()
#     device_public_key = models.TextField(null=True, blank=True)  # ← add this
#     allowed_location = models.CharField(max_length=255)
#     is_sealed = models.BooleanField(default=True)
#     total_shares = models.IntegerField()
#     threshold = models.IntegerField()
#     device_id = models.CharField(max_length=255, null=True, blank=True)


class VaultConfig(models.Model):
    encrypted_root_key = models.BinaryField()

    # WebAuthn fields
    credential_id = models.BinaryField(null=True)
    public_key = models.BinaryField(null=True)
    sign_count = models.IntegerField(default=0)

    allowed_location = models.CharField(max_length=255)
    is_sealed = models.BooleanField(default=True)

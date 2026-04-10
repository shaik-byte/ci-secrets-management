import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.db import migrations, models


def _encrypt_app_password(password: str) -> bytes:
    kek = base64.urlsafe_b64decode(settings.VAULT_KEK)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)
    return nonce + ciphertext


def forwards_encrypt_passwords(apps, schema_editor):
    EmailConfig = apps.get_model("notifications", "EmailConfig")

    for cfg in EmailConfig.objects.exclude(app_password__isnull=True).exclude(app_password=""):
        cfg.app_password_encrypted = _encrypt_app_password(cfg.app_password)
        cfg.save(update_fields=["app_password_encrypted"])


def backwards_noop(apps, schema_editor):
    # Lossless reverse is not possible once plaintext column is removed.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("notifications", "0002_emailconfig_notified"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailconfig",
            name="app_password_encrypted",
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.RunPython(forwards_encrypt_passwords, backwards_noop),
        migrations.RemoveField(
            model_name="emailconfig",
            name="app_password",
        ),
    ]

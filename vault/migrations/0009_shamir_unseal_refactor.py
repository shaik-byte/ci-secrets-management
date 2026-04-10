from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0008_remove_fingerprint_uniqueness"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="vaultconfig",
            name="credential_id",
        ),
        migrations.RemoveField(
            model_name="vaultconfig",
            name="public_key",
        ),
        migrations.RemoveField(
            model_name="vaultconfig",
            name="sign_count",
        ),
        migrations.AddField(
            model_name="vaultconfig",
            name="threshold",
            field=models.IntegerField(default=3),
        ),
        migrations.AddField(
            model_name="vaultconfig",
            name="total_shares",
            field=models.IntegerField(default=5),
        ),
        migrations.DeleteModel(
            name="WebAuthnDevice",
        ),
    ]

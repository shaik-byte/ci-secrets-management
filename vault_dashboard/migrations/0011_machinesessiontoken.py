from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("vault_dashboard", "0010_machine_auth_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="MachineSessionToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(max_length=128, unique=True)),
                ("subject", models.CharField(blank=True, default="", max_length=255)),
                ("issuer", models.CharField(blank=True, default="", max_length=255)),
                ("audience", models.CharField(blank=True, default="", max_length=255)),
                ("jwt_id", models.CharField(blank=True, default="", max_length=255)),
                ("claims_snapshot", models.JSONField(blank=True, default=dict)),
                ("expires_at", models.DateTimeField()),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("jwt_identity", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="session_tokens", to="vault_dashboard.jwtworkloadidentity")),
                ("machine_policy", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="session_tokens", to="vault_dashboard.machinepolicy")),
            ],
        ),
    ]

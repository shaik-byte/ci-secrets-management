from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("vault_dashboard", "0014_userfeatureaccess"),
    ]

    operations = [
        migrations.CreateModel(
            name="EnvironmentSecretPolicy",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("secret_value_regex", models.CharField(blank=True, default="", max_length=500)),
                ("regex_mode", models.CharField(choices=[("match", "Should Match"), ("not_match", "Should Not Match")], default="match", max_length=20)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("environment", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="secret_policy", to="vault_dashboard.environment")),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="updated_environment_secret_policies", to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]

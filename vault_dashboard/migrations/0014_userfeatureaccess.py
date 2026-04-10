from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("vault_dashboard", "0013_environment_require_admin_delete_approval"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserFeatureAccess",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("feature_key", models.CharField(max_length=64)),
                ("can_view", models.BooleanField(default=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="feature_access_rules", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "unique_together": {("user", "feature_key")},
            },
        ),
        migrations.AddIndex(
            model_name="userfeatureaccess",
            index=models.Index(fields=["feature_key", "can_view"], name="vault_dashbo_feature_2b6af2_idx"),
        ),
    ]

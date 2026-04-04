from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vault_dashboard", "0012_deletionapprovalrequest"),
    ]

    operations = [
        migrations.AddField(
            model_name="environment",
            name="require_admin_delete_approval",
            field=models.BooleanField(default=True),
        ),
    ]

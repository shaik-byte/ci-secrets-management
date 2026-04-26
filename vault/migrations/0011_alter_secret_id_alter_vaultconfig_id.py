from django.db import migrations


class Migration(migrations.Migration):
    """
    Compatibility migration.

    Retained as a no-op so existing databases/environments that reference this
    migration filename continue to load migration dependencies successfully.
    """

    dependencies = [
        ("vault", "0010_remove_vaultconfig_is_sealed_vaultconfig_created_at_and_more"),
    ]

    operations = []

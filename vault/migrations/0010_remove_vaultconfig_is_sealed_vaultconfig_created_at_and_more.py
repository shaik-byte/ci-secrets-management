from django.db import migrations


class Migration(migrations.Migration):
    """
    Placeholder migration to restore a missing dependency node.

    Some environments have a subsequent migration
    `0011_alter_secret_id_alter_vaultconfig_id` that depends on this
    migration name. Keeping this as a no-op preserves migration graph
    consistency across clones.
    """

    dependencies = [
        ("vault", "0009_shamir_unseal_refactor"),
    ]

    operations = []

from django.db import migrations


class Migration(migrations.Migration):
    """
    Compatibility migration.

    Some environments generated this migration name locally and then produced
    a follow-up 0011 migration that depends on it. Keeping this no-op migration
    in the canonical tree prevents NodeNotFoundError during graph loading.
    """

    dependencies = [
        ("vault", "0009_shamir_unseal_refactor"),
    ]

    operations = []

from django.db import migrations


class Migration(migrations.Migration):
    """
    Compatibility migration.

    Kept as a no-op to preserve stable migration numbering while depending on
    the canonical prior migration in this repository.
    """

    dependencies = [
        ("vault", "0009_shamir_unseal_refactor"),
    ]

    operations = []

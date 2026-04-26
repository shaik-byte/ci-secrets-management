from django.db import migrations


def ensure_is_sealed_column(apps, schema_editor):
    VaultConfig = apps.get_model("vault", "VaultConfig")
    table_name = VaultConfig._meta.db_table
    connection = schema_editor.connection

    with connection.cursor() as cursor:
        columns = {
            col.name
            for col in connection.introspection.get_table_description(cursor, table_name)
        }

    if "is_sealed" not in columns:
        field = VaultConfig._meta.get_field("is_sealed")
        schema_editor.add_field(VaultConfig, field)


def drop_is_sealed_column_if_exists(apps, schema_editor):
    VaultConfig = apps.get_model("vault", "VaultConfig")
    table_name = VaultConfig._meta.db_table
    connection = schema_editor.connection

    with connection.cursor() as cursor:
        columns = {
            col.name
            for col in connection.introspection.get_table_description(cursor, table_name)
        }

    if "is_sealed" in columns:
        field = VaultConfig._meta.get_field("is_sealed")
        schema_editor.remove_field(VaultConfig, field)


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0011_alter_secret_id_alter_vaultconfig_id"),
    ]

    operations = [
        migrations.RunPython(
            ensure_is_sealed_column,
            reverse_code=drop_is_sealed_column_if_exists,
        ),
    ]

from django.db import migrations, models


def copy_owner_email_to_folder(apps, schema_editor):
    Folder = apps.get_model('vault_dashboard', 'Folder')
    Secret = apps.get_model('vault_dashboard', 'Secret')

    for folder in Folder.objects.all():
        owner = (
            Secret.objects.filter(folder_id=folder.id)
            .exclude(owner_email='')
            .values_list('owner_email', flat=True)
            .first()
        )
        if owner:
            folder.owner_email = owner
            folder.save(update_fields=['owner_email'])


class Migration(migrations.Migration):

    dependencies = [
        ('vault_dashboard', '0006_secret_service_owner'),
    ]

    operations = [
        migrations.AddField(
            model_name='folder',
            name='owner_email',
            field=models.EmailField(blank=True, default='', max_length=254),
        ),
        migrations.RunPython(copy_owner_email_to_folder, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='secret',
            name='owner_email',
        ),
    ]

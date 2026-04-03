from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('vault_dashboard', '0007_move_owner_email_to_folder'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('can_read', models.BooleanField(default=False)),
                ('can_write', models.BooleanField(default=False)),
                ('can_delete', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('environment', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_policies', to='vault_dashboard.environment')),
                ('folder', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_policies', to='vault_dashboard.folder')),
                ('secret', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='access_policies', to='vault_dashboard.secret')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vault_access_policies', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]

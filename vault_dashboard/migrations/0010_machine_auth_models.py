from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('vault_dashboard', '0009_policy_groups'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='MachinePolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('description', models.CharField(blank=True, default='', max_length=300)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('access_policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='machine_policies', to='vault_dashboard.accesspolicy')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_machine_policies', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='JWTWorkloadIdentity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('issuer', models.CharField(max_length=255)),
                ('audience', models.CharField(max_length=255)),
                ('subject_pattern', models.CharField(blank=True, default='', max_length=255)),
                ('jwks_url', models.URLField(blank=True, default='')),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('machine_policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='jwt_identities', to='vault_dashboard.machinepolicy')),
            ],
        ),
        migrations.CreateModel(
            name='AppRole',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=120, unique=True)),
                ('role_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('secret_id_hash', models.CharField(max_length=128)),
                ('bound_cidrs', models.CharField(blank=True, default='', max_length=300)),
                ('token_ttl_seconds', models.IntegerField(default=3600)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('machine_policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approles', to='vault_dashboard.machinepolicy')),
            ],
        ),
    ]

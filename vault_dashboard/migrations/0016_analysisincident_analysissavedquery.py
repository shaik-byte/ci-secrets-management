from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("vault_dashboard", "0015_environmentsecretpolicy"),
    ]

    operations = [
        migrations.CreateModel(
            name="AnalysisIncident",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("incident_key", models.CharField(max_length=191, unique=True)),
                ("username", models.CharField(max_length=150)),
                ("action", models.CharField(max_length=50)),
                ("entity", models.CharField(max_length=100)),
                ("risk_score", models.IntegerField(default=0)),
                ("severity", models.CharField(default="low", max_length=20)),
                ("event_count", models.IntegerField(default=0)),
                ("source_ip_count", models.IntegerField(default=0)),
                ("reasons", models.JSONField(blank=True, default=list)),
                ("summary", models.CharField(blank=True, default="", max_length=500)),
                ("environment_label", models.CharField(blank=True, default="default", max_length=100)),
                ("cluster_label", models.CharField(blank=True, default="primary", max_length=100)),
                ("status", models.CharField(choices=[("open", "Open"), ("investigating", "Investigating"), ("resolved", "Resolved")], default="open", max_length=20)),
                ("false_positive", models.BooleanField(default=False)),
                ("analyst_notes", models.TextField(blank=True, default="")),
                ("routing_status", models.CharField(blank=True, default="", max_length=200)),
                ("first_seen_at", models.DateTimeField(blank=True, null=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("last_analyzed_at", models.DateTimeField(auto_now=True)),
                ("assignee", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="analysis_incidents", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-risk_score", "-last_analyzed_at"]},
        ),
        migrations.CreateModel(
            name="AnalysisSavedQuery",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120)),
                ("query", models.CharField(max_length=500)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="analysis_saved_queries", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["name"], "unique_together": {("user", "name")}},
        ),
    ]

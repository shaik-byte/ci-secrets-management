from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import JSONField
import uuid


class Environment(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    require_admin_delete_approval = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Folder(models.Model):
    name = models.CharField(max_length=255)
    owner_email = models.EmailField(blank=True, default="")
    environment = models.ForeignKey(Environment, on_delete=models.CASCADE, related_name="folders")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.environment.name} / {self.name}"

    @property
    def risk_score(self):
        secrets = list(self.secrets.all())

        if not secrets:
            return 100

        today = timezone.now().date()
        scores = []

        for secret in secrets:
            score = 100

            if not secret.service_name:
                score -= 5

            if not self.owner_email:
                score -= 10

            if secret.expire_date:
                days_left = (secret.expire_date - today).days
                if days_left < 0:
                    score -= 50
                elif days_left <= 7:
                    score -= 25
                elif days_left <= 30:
                    score -= 10

            if secret.is_access_enabled:
                score -= 10

            scores.append(max(score, 0))

        return round(sum(scores) / len(scores))


class Secret(models.Model):
    name = models.CharField(max_length=255)
    service_name = models.CharField(max_length=255, blank=True, default="")
    encrypted_value = models.BinaryField()
    notified = models.BooleanField(default=False)
    is_access_enabled = models.BooleanField(default=False)
    expire_date = models.DateField(null=True, blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name="secrets")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class SecretPolicy(models.Model):
    MATCH_MODE_CHOICES = [
        ("match", "Should Match"),
        ("not_match", "Should Not Match"),
    ]

    created_by = models.OneToOneField(User, on_delete=models.CASCADE)
    secret_value_regex = models.CharField(max_length=500, blank=True, default="")
    regex_mode = models.CharField(max_length=20, choices=MATCH_MODE_CHOICES, default="match")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Secret Policy - {self.created_by.username}"


class AccessPolicy(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="vault_access_policies")
    environment = models.ForeignKey(Environment, on_delete=models.CASCADE, null=True, blank=True, related_name="access_policies")
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE, null=True, blank=True, related_name="access_policies")
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, null=True, blank=True, related_name="access_policies")
    can_read = models.BooleanField(default=False)
    can_write = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        scope = "global"
        if self.secret_id:
            scope = f"secret:{self.secret_id}"
        elif self.folder_id:
            scope = f"folder:{self.folder_id}"
        elif self.environment_id:
            scope = f"environment:{self.environment_id}"
        return f"{self.user.username} [{scope}]"


class PolicyGroup(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.CharField(max_length=300, blank=True, default="")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_policy_groups")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class PolicyGroupMembership(models.Model):
    group = models.ForeignKey(PolicyGroup, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="policy_group_memberships")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("group", "user")

    def __str__(self):
        return f"{self.group.name} -> {self.user.username}"


class PolicyGroupPolicy(models.Model):
    group = models.ForeignKey(PolicyGroup, on_delete=models.CASCADE, related_name="policy_links")
    policy = models.ForeignKey(AccessPolicy, on_delete=models.CASCADE, related_name="group_links")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("group", "policy")

    def __str__(self):
        return f"{self.group.name} -> policy:{self.policy_id}"


class MachinePolicy(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.CharField(max_length=300, blank=True, default="")
    access_policy = models.ForeignKey(AccessPolicy, on_delete=models.CASCADE, related_name="machine_policies")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="created_machine_policies")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class AppRole(models.Model):
    name = models.CharField(max_length=120, unique=True)
    role_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    secret_id_hash = models.CharField(max_length=128)
    bound_cidrs = models.CharField(max_length=300, blank=True, default="")
    token_ttl_seconds = models.IntegerField(default=3600)
    machine_policy = models.ForeignKey(MachinePolicy, on_delete=models.CASCADE, related_name="approles")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AppRole<{self.name}>"


class JWTWorkloadIdentity(models.Model):
    name = models.CharField(max_length=120, unique=True)
    issuer = models.CharField(max_length=255)
    audience = models.CharField(max_length=255)
    subject_pattern = models.CharField(max_length=255, blank=True, default="")
    jwks_url = models.URLField(blank=True, default="")
    machine_policy = models.ForeignKey(MachinePolicy, on_delete=models.CASCADE, related_name="jwt_identities")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"JWT<{self.name}>"


class MachineSessionToken(models.Model):
    token_hash = models.CharField(max_length=128, unique=True)
    machine_policy = models.ForeignKey(MachinePolicy, on_delete=models.CASCADE, related_name="session_tokens")
    jwt_identity = models.ForeignKey(JWTWorkloadIdentity, on_delete=models.SET_NULL, null=True, blank=True, related_name="session_tokens")
    subject = models.CharField(max_length=255, blank=True, default="")
    issuer = models.CharField(max_length=255, blank=True, default="")
    audience = models.CharField(max_length=255, blank=True, default="")
    jwt_id = models.CharField(max_length=255, blank=True, default="")
    claims_snapshot = JSONField(default=dict, blank=True)
    expires_at = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"MachineSession<{self.machine_policy.name}>"


class DeletionApprovalRequest(models.Model):
    TARGET_CHOICES = [
        ("environment", "Environment"),
        ("folder", "Folder"),
        ("secret", "Secret"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]

    target_type = models.CharField(max_length=20, choices=TARGET_CHOICES)
    target_id = models.PositiveIntegerField()
    target_name = models.CharField(max_length=255)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="deletion_requests")
    approver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="processed_deletion_requests")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    request_note = models.CharField(max_length=300, blank=True, default="")
    decision_note = models.CharField(max_length=300, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.target_type}:{self.target_name} ({self.status})"


class UserFeatureAccess(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="feature_access_rules")
    feature_key = models.CharField(max_length=64)
    can_view = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "feature_key")
        indexes = [
            models.Index(fields=["feature_key", "can_view"]),
        ]

    def __str__(self):
        return f"{self.user.username}:{self.feature_key}={self.can_view}"


class EnvironmentSecretPolicy(models.Model):
    MATCH_MODE_CHOICES = [
        ("match", "Should Match"),
        ("not_match", "Should Not Match"),
    ]

    environment = models.OneToOneField(Environment, on_delete=models.CASCADE, related_name="secret_policy")
    secret_value_regex = models.CharField(max_length=500, blank=True, default="")
    regex_mode = models.CharField(max_length=20, choices=MATCH_MODE_CHOICES, default="match")
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="updated_environment_secret_policies")
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Env Policy - {self.environment.name}"


class AnalysisIncident(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("investigating", "Investigating"),
        ("resolved", "Resolved"),
    ]
    incident_key = models.CharField(max_length=191, unique=True)
    username = models.CharField(max_length=150)
    action = models.CharField(max_length=50)
    entity = models.CharField(max_length=100)
    risk_score = models.IntegerField(default=0)
    severity = models.CharField(max_length=20, default="low")
    event_count = models.IntegerField(default=0)
    source_ip_count = models.IntegerField(default=0)
    reasons = JSONField(default=list, blank=True)
    summary = models.CharField(max_length=500, blank=True, default="")
    environment_label = models.CharField(max_length=100, blank=True, default="default")
    cluster_label = models.CharField(max_length=100, blank=True, default="primary")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open")
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="analysis_incidents")
    false_positive = models.BooleanField(default=False)
    analyst_notes = models.TextField(blank=True, default="")
    routing_status = models.CharField(max_length=200, blank=True, default="")
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_analyzed_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-risk_score", "-last_analyzed_at"]

    def __str__(self):
        return f"{self.incident_key} ({self.severity})"


class AnalysisSavedQuery(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="analysis_saved_queries")
    name = models.CharField(max_length=120)
    query = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "name")
        ordering = ["name"]

    def __str__(self):
        return f"{self.user.username}:{self.name}"

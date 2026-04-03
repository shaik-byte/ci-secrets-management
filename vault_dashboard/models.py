from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Environment(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
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

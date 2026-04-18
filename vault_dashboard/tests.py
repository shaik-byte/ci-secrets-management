import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase

from .models import AccessPolicy, Environment, Folder
from . import views as dashboard_views


class AccessPolicySyncStateTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="root", email="root@example.com", password="rootpass")
        self.target = User.objects.create_user(username="alice", email="alice@example.com", password="alicepass")
        self.client.force_login(self.admin)

    def test_sync_state_reflects_policy_changes(self):
        response = self.client.get("/secrets/cli/policies/sync-state/")
        self.assertEqual(response.status_code, 200)
        initial_payload = response.json()
        self.assertEqual(initial_payload["rule_count"], 0)
        self.assertEqual(initial_payload["policy_sync_token"], "none:0")

        AccessPolicy.objects.create(user=self.target, can_read=True, can_write=False, can_delete=False)

        updated_response = self.client.get("/secrets/cli/policies/sync-state/")
        self.assertEqual(updated_response.status_code, 200)
        updated_payload = updated_response.json()
        self.assertEqual(updated_payload["rule_count"], 1)
        self.assertNotEqual(updated_payload["policy_sync_token"], initial_payload["policy_sync_token"])

    def test_cli_apply_policy_updates_sync_state(self):
        before_response = self.client.get("/secrets/cli/policies/sync-state/")
        before_payload = before_response.json()

        document = {
            "rules": [
                {
                    "user": self.target.username,
                    "permissions": {"read": True, "write": True, "delete": False},
                }
            ]
        }
        apply_response = self.client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps({"policy_document": json.dumps(document), "document_format": "json"}),
            content_type="application/json",
        )
        self.assertEqual(apply_response.status_code, 200)
        self.assertEqual(apply_response.json()["updated_rules"], 1)

        after_response = self.client.get("/secrets/cli/policies/sync-state/")
        after_payload = after_response.json()

        self.assertEqual(after_payload["rule_count"], 1)
        self.assertNotEqual(after_payload["policy_sync_token"], before_payload["policy_sync_token"])


class AccessScopeVisibilityTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner", email="owner@example.com", password="ownerpass")
        self.user = User.objects.create_user(username="cooper", email="cooper@example.com", password="cooperpass")
        self.client.force_login(self.user)
        session = self.client.session
        session["vault_key"] = "dummy-session-key"
        session.save()

        self.environment = Environment.objects.create(name="test", created_by=self.owner)
        self.allowed_folder = Folder.objects.create(name="shaik", environment=self.environment, owner_email="a@test.com")
        self.denied_folder = Folder.objects.create(name="private", environment=self.environment, owner_email="b@test.com")

    def test_dashboard_shows_only_policy_allowed_folder(self):
        AccessPolicy.objects.create(
            user=self.user,
            environment=self.environment,
            folder=self.allowed_folder,
            can_read=True,
            can_write=False,
            can_delete=False,
        )

        response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn("shaik", html)
        self.assertNotIn("private", html)

    def test_cli_apply_policy_resolves_folder_within_environment_scope(self):
        other_environment = Environment.objects.create(name="other", created_by=self.owner)
        Folder.objects.create(name="shaik", environment=other_environment, owner_email="other@test.com")

        document = {
            "rules": [
                {
                    "user": self.user.username,
                    "environment": "test",
                    "folder": "shaik",
                    "permissions": {"read": True},
                }
            ]
        }
        admin_client = self.client_class()
        admin_client.force_login(self.owner)
        response = admin_client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps({"policy_document": json.dumps(document), "document_format": "json"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root2", "root2@example.com", "rootpass"))
        response = super_client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps({"policy_document": json.dumps(document), "document_format": "json"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

        policy = AccessPolicy.objects.get(user=self.user, can_read=True)
        self.assertEqual(policy.environment_id, self.environment.id)
        self.assertEqual(policy.folder_id, self.allowed_folder.id)

    def test_dashboard_uses_fallback_when_visibility_helper_missing(self):
        with patch.dict(dashboard_views.__dict__, {"_visible_environments_for_user": None}):
            response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)
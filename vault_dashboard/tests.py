import json

from django.contrib.auth.models import User
from django.test import TestCase

from .models import AccessPolicy


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

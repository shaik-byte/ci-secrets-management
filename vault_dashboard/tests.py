import json
import re
from pathlib import Path
from unittest.mock import patch
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from cryptography.fernet import Fernet

from .models import AccessPolicy, AppRole, Environment, Folder, MachinePolicy, MachineSessionToken, Secret
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
        self.root_key = b"0123456789abcdef0123456789abcdef"
        session = self.client.session
        session["vault_key"] = base64.b64encode(self.root_key).decode()
        session.save()

        self.environment = Environment.objects.create(name="test", created_by=self.owner)
        self.allowed_folder = Folder.objects.create(name="shaik", environment=self.environment, owner_email="a@test.com")
        self.denied_folder = Folder.objects.create(name="private", environment=self.environment, owner_email="b@test.com")
        fernet = Fernet(base64.urlsafe_b64encode(self.root_key))
        self.secret = Secret.objects.create(
            name="API_KEY",
            service_name="svc",
            encrypted_value=fernet.encrypt(b"super-secret"),
            folder=self.allowed_folder,
        )
        self.other_secret = Secret.objects.create(
            name="DB_PASSWORD",
            service_name="svc",
            encrypted_value=fernet.encrypt(b"other-secret"),
            folder=self.allowed_folder,
        )

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
        self.assertEqual(response.json()["skipped_rules"], 0)

    def test_cli_apply_policy_accepts_case_insensitive_user_and_scope_names(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root3", "root3@example.com", "rootpass"))
        response = super_client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps(
                {
                    "policy_document": json.dumps(
                        {
                            "rules": [
                                {
                                    "user": "COOPER",
                                    "environment": "TEST",
                                    "folder": "SHAIK",
                                    "permissions": {"read": True},
                                }
                            ]
                        }
                    ),
                    "document_format": "json",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated_rules"], 1)
        self.assertEqual(response.json()["skipped_rules"], 0)

        policy = AccessPolicy.objects.get(user=self.user, environment=self.environment, folder=self.allowed_folder)
        self.assertTrue(policy.can_read)

    def test_dashboard_uses_fallback_when_visibility_helper_missing(self):
        with patch.dict(dashboard_views.__dict__, {"_visible_environments_for_user": None}):
            response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)

    def test_copy_secret_allowed_when_read_policy_exists_even_if_admin_lock_flag_is_false(self):
        AccessPolicy.objects.create(
            user=self.user,
            environment=self.environment,
            folder=self.allowed_folder,
            secret=self.secret,
            can_read=True,
            can_write=True,
            can_delete=True,
        )
        self.secret.is_access_enabled = False
        self.secret.save(update_fields=["is_access_enabled"])

        response = self.client.get(f"/secrets/copy-secret/{self.secret.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("secret"), "super-secret")

    def test_read_only_policy_hides_edit_and_delete_actions_for_secret(self):
        AccessPolicy.objects.create(
            user=self.user,
            environment=self.environment,
            folder=self.allowed_folder,
            secret=self.secret,
            can_read=True,
            can_write=False,
            can_delete=False,
        )
        response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn(f"copySecret({self.secret.id})", html)
        self.assertNotIn(f"editSecretModal{self.secret.id}", html)
        self.assertNotIn(f"deleteSecretModal{self.secret.id}", html)

    def test_write_and_delete_policies_show_edit_and_delete_actions_for_secret(self):
        AccessPolicy.objects.create(
            user=self.user,
            environment=self.environment,
            folder=self.allowed_folder,
            secret=self.secret,
            can_read=True,
            can_write=True,
            can_delete=True,
        )
        response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn(f"editSecretModal{self.secret.id}", html)
        self.assertIn(f"deleteSecretModal{self.secret.id}", html)

    def test_cli_secret_scoped_policy_exposes_only_target_secret(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root4", "root4@example.com", "rootpass"))
        response = super_client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps(
                {
                    "policy_document": json.dumps(
                        {
                            "rules": [
                                {
                                    "user": self.user.username,
                                    "environment": self.environment.name,
                                    "folder": self.allowed_folder.name,
                                    "secret": self.secret.name,
                                    "permissions": {"read": True, "write": False, "delete": False},
                                }
                            ]
                        }
                    ),
                    "document_format": "json",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated_rules"], 1)
        self.assertEqual(response.json()["skipped_rules"], 0)

        page = self.client.get("/secrets/")
        self.assertEqual(page.status_code, 200)
        html = page.content.decode("utf-8")
        self.assertIn(self.secret.name, html)
        self.assertNotIn(self.other_secret.name, html)

        allowed_copy = self.client.get(f"/secrets/copy-secret/{self.secret.id}/")
        denied_copy = self.client.get(f"/secrets/copy-secret/{self.other_secret.id}/")
        self.assertEqual(allowed_copy.status_code, 200)
        self.assertEqual(denied_copy.status_code, 403)

    def test_ui_secret_scoped_policy_exposes_only_target_secret(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root5", "root5@example.com", "rootpass"))
        response = super_client.post(
            "/secrets/policy-engine/save-ui/",
            data={
                "user_id": self.user.id,
                "environment_id": self.environment.id,
                "folder_id": self.allowed_folder.id,
                "secret_id": self.secret.id,
                "can_read": "on",
            },
        )
        self.assertEqual(response.status_code, 302)

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
        self.assertEqual(response.json()["skipped_rules"], 0)

    def test_cli_apply_policy_accepts_case_insensitive_user_and_scope_names(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root3", "root3@example.com", "rootpass"))
        response = super_client.post(
            "/secrets/cli/policies/apply/",
            data=json.dumps(
                {
                    "policy_document": json.dumps(
                        {
                            "rules": [
                                {
                                    "user": "COOPER",
                                    "environment": "TEST",
                                    "folder": "SHAIK",
                                    "permissions": {"read": True},
                                }
                            ]
                        }
                    ),
                    "document_format": "json",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["updated_rules"], 1)
        self.assertEqual(response.json()["skipped_rules"], 0)

        policy = AccessPolicy.objects.get(user=self.user, environment=self.environment, folder=self.allowed_folder)
        self.assertTrue(policy.can_read)

    def test_dashboard_uses_fallback_when_visibility_helper_missing(self):
        with patch.dict(dashboard_views.__dict__, {"_visible_environments_for_user": None}):
            response = self.client.get("/secrets/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status_code, 200)

    def test_policy_ui_can_create_new_user_with_password_and_attach_policy(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root6", "root6@example.com", "rootpass"))

        response = super_client.post(
            "/secrets/policy-engine/save-ui/",
            data={
                "new_username": "newpolicyuser",
                "new_password": "newpolicypass",
                "environment_id": self.environment.id,
                "folder_id": self.allowed_folder.id,
                "can_read": "on",
            },
        )
        self.assertEqual(response.status_code, 302)

        created_user = User.objects.get(username="newpolicyuser")
        self.assertTrue(created_user.check_password("newpolicypass"))
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=created_user,
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
            ).exists()
        )

    def test_policy_ui_requires_user_or_new_credentials(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root7", "root7@example.com", "rootpass"))

        response = super_client.post(
            "/secrets/policy-engine/save-ui/",
            data={
                "environment_id": self.environment.id,
                "can_read": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(username="").exists())
        self.assertEqual(AccessPolicy.objects.count(), 0)

    def test_policy_document_can_create_new_user_with_password_and_attach_policy(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root8", "root8@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "user": "manualdocuser",
                    "password": "manualdocpass",
                    "environment": self.environment.name,
                    "folder": self.allowed_folder.name,
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)

        created_user = User.objects.get(username="manualdocuser")
        self.assertTrue(created_user.check_password("manualdocpass"))
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=created_user,
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
            ).exists()
        )

    def test_policy_document_can_create_new_user_with_new_username_and_new_password_keys(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root10", "root10@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "new_username": "manualdocaliasuser",
                    "new_password": "manualdocaliaspass",
                    "environment": self.environment.name,
                    "folder": self.allowed_folder.name,
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)

        created_user = User.objects.get(username="manualdocaliasuser")
        self.assertTrue(created_user.check_password("manualdocaliaspass"))
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=created_user,
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
            ).exists()
        )

    def test_policy_document_can_create_user_when_new_username_flag_is_true(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root12", "root12@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "user": "alice",
                    "new_username": "true",
                    "password": "alice-pass",
                    "environment": self.environment.name,
                    "folder": self.allowed_folder.name,
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)

        created_user = User.objects.get(username="alice")
        self.assertTrue(created_user.check_password("alice-pass"))
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=created_user,
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
                can_write=False,
                can_delete=False,
            ).exists()
        )

    def test_policy_document_with_new_username_flag_true_updates_existing_user_policy(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root13", "root13@example.com", "rootpass"))
        existing_user = User.objects.create_user(username="alice", password="old-pass")

        document = {
            "rules": [
                {
                    "user": "alice",
                    "new_username": "true",
                    "password": "alice-pass",
                    "environment": self.environment.name,
                    "folder": self.allowed_folder.name,
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)

        existing_user.refresh_from_db()
        self.assertTrue(existing_user.check_password("old-pass"))
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=existing_user,
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
                can_write=False,
                can_delete=False,
            ).exists()
        )

    def test_policy_document_supports_wildcard_scope_with_star(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root14", "root14@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "user": "alice",
                    "new_username": "true",
                    "password": "alice-pass",
                    "environment": "*",
                    "folder": "*",
                    "secret": "*",
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="alice")
        self.assertTrue(
            AccessPolicy.objects.filter(
                user=user,
                environment__isnull=True,
                folder__isnull=True,
                secret__isnull=True,
                can_read=True,
                can_write=False,
                can_delete=False,
            ).exists()
        )

    def test_policy_document_supports_multiple_folders_and_secrets(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root15", "root15@example.com", "rootpass"))
        other_folder = Folder.objects.create(name="billing", environment=self.environment, owner_email="c@test.com")
        secret_1 = Secret.objects.create(name="STRIPE_API_KEY", encrypted_value=b"x", folder=self.allowed_folder)
        secret_2 = Secret.objects.create(name="STRIPE_WEBHOOK_SECRET", encrypted_value=b"y", folder=other_folder)

        document = {
            "rules": [
                {
                    "user": "alice",
                    "new_username": "true",
                    "password": "alice-pass",
                    "environment": self.environment.name,
                    "folder": f"{self.allowed_folder.name},{other_folder.name}",
                    "secret": f"{secret_1.name},{secret_2.name}",
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)

        user = User.objects.get(username="alice")
        self.assertEqual(
            AccessPolicy.objects.filter(user=user, environment=self.environment, can_read=True).count(),
            2,
        )

    def test_policy_document_requires_user_in_each_rule(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root9", "root9@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "environment": self.environment.name,
                    "folder": self.allowed_folder.name,
                    "permissions": {"read": True, "write": False, "delete": False},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(username="defaultdocuser").exists())
        self.assertFalse(
            AccessPolicy.objects.filter(
                environment=self.environment,
                folder=self.allowed_folder,
                can_read=True,
            ).exists()
        )

    def test_policy_document_does_not_create_user_when_rule_scope_is_invalid(self):
        super_client = self.client_class()
        super_client.force_login(User.objects.create_superuser("root11", "root11@example.com", "rootpass"))

        document = {
            "rules": [
                {
                    "new_username": "orphaneduser",
                    "new_password": "orphanedpass",
                    "environment": "does-not-exist",
                    "permissions": {"read": True},
                }
            ]
        }
        response = super_client.post(
            "/secrets/policy-engine/save-document/",
            data={
                "policy_document": json.dumps(document),
                "document_format": "json",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(username="orphaneduser").exists())
        self.assertEqual(AccessPolicy.objects.count(), 0)


class AppRoleMachineLoginTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner_machine", email="owner_machine@example.com", password="ownerpass")
        self.machine_user = User.objects.create_user(
            username="machine_user",
            email="machine_user@example.com",
            password="machinepass",
        )
        self.environment = Environment.objects.create(name="prod", created_by=self.owner)
        self.access_policy = AccessPolicy.objects.create(
            user=self.machine_user,
            environment=self.environment,
            can_read=True,
            can_write=False,
            can_delete=False,
        )
        self.machine_policy = MachinePolicy.objects.create(
            name="svc-prod-reader",
            description="Service reader policy",
            access_policy=self.access_policy,
            created_by=self.owner,
        )
        self.secret_id_plain = "known-secret-id"
        self.approle = AppRole.objects.create(
            name="svc-prod-approle",
            secret_id_hash=dashboard_views.hashlib.sha256(self.secret_id_plain.encode()).hexdigest(),
            machine_policy=self.machine_policy,
            token_ttl_seconds=1200,
            is_active=True,
        )

    def test_unauthenticated_approle_machine_login_does_not_redirect_to_login(self):
        response = self.client.post(
            "/secrets/policy-engine/machine/approle/login/",
            data=json.dumps({"role_id": str(self.approle.role_id), "secret_id": self.secret_id_plain}),
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code, 302)
        self.assertNotIn("/login/", response.headers.get("Location", ""))
        self.assertEqual(response.status_code, 200)

    def test_approle_machine_login_returns_machine_token_with_policy_scope(self):
        response = self.client.post(
            "/secrets/policy-engine/machine/approle/login/",
            data=json.dumps({"role_id": str(self.approle.role_id), "secret_id": self.secret_id_plain}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("machine_token", payload)
        self.assertEqual(payload["machine_policy"], self.machine_policy.name)
        self.assertEqual(payload["expires_in"], 1200)
        self.assertEqual(payload["access"]["scope"], f"environment:{self.environment.id}")
        self.assertTrue(MachineSessionToken.objects.filter(machine_policy=self.machine_policy).exists())

    def test_approle_machine_login_rejects_invalid_secret(self):
        response = self.client.post(
            "/secrets/policy-engine/machine/approle/login/",
            data=json.dumps({"role_id": str(self.approle.role_id), "secret_id": "wrong-secret"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(MachineSessionToken.objects.filter(machine_policy=self.machine_policy).exists())

    def test_approle_machine_login_get_returns_405_json(self):
        response = self.client.get("/secrets/policy-engine/machine/approle/login/")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_approle_machine_login_invalid_role_id_format_returns_400_json(self):
        response = self.client.post(
            "/secrets/policy-engine/machine/approle/login/",
            data=json.dumps({"role_id": "test", "secret_id": self.secret_id_plain}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/json")


class MergeConflictMarkerRegressionTests(TestCase):
    def test_views_file_has_no_merge_conflict_markers(self):
        content = Path(__file__).with_name("views.py").read_text(encoding="utf-8")
        marker_pattern = re.compile(r"^(<<<<<<<|=======|>>>>>>>)", re.MULTILINE)
        self.assertIsNone(marker_pattern.search(content))


class AppRoleSecretVisibilityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(username="policyadmin", email="policy@example.com", password="pass1234")
        self.client.force_login(self.user)
        self.environment = Environment.objects.create(name="prod", created_by=self.user)
        self.folder = Folder.objects.create(name="apps", environment=self.environment, owner_email="owner@example.com")
        self.secret = Secret.objects.create(name="API_KEY", service_name="svc", encrypted_value=b"x", folder=self.folder)
        self.policy = AccessPolicy.objects.create(user=self.user, secret=self.secret, can_read=True, can_write=True, can_delete=True)
        self.machine_policy = MachinePolicy.objects.create(name="build-agent", access_policy=self.policy, created_by=self.user)
        session = self.client.session
        session["vault_key"] = "dummy-session-key"
        session.save()

    def test_new_approle_secret_remains_visible_on_dashboard_refresh(self):
        response = self.client.post(
            "/secrets/policy-engine/machine/save-approle/",
            data={
                "name": "gha-role",
                "machine_policy_id": str(self.machine_policy.id),
                "bound_cidrs": "10.0.0.0/24",
                "token_ttl_seconds": "3600",
                "is_active": "on",
            },
        )
        self.assertEqual(response.status_code, 302)

        first_load = self.client.get("/secrets/")
        self.assertEqual(first_load.status_code, 200)
        generated_secret = first_load.context["new_approle_secret"]
        self.assertTrue(generated_secret)

        refresh = self.client.get("/secrets/")
        self.assertEqual(refresh.status_code, 200)
        self.assertEqual(refresh.context["new_approle_secret"], generated_secret)

class MachineTokenSecretListTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner_api", email="owner_api@example.com", password="ownerpass")
        self.machine_user = User.objects.create_user(username="machine_api", email="machine_api@example.com", password="machinepass")
        self.environment = Environment.objects.create(name="test", created_by=self.owner)
        self.folder = Folder.objects.create(name="shaik", environment=self.environment, owner_email="svc@example.com")
        self.secret = Secret.objects.create(name="TOKEN", service_name="svc", encrypted_value=b"x", folder=self.folder)

    def _create_machine_token(self, *, can_read=True, expires_at=None, environment=None, folder=None):
        access = AccessPolicy.objects.create(
            user=self.machine_user,
            environment=environment,
            folder=folder,
            can_read=can_read,
            can_write=False,
            can_delete=False,
        )
        machine_policy = MachinePolicy.objects.create(
            name=f"machine-policy-{MachinePolicy.objects.count()+1}",
            access_policy=access,
            created_by=self.owner,
        )
        plain = f"mvt_plain_{MachineSessionToken.objects.count()+1}"
        MachineSessionToken.objects.create(
            token_hash=dashboard_views.hashlib.sha256(plain.encode()).hexdigest(),
            machine_policy=machine_policy,
            expires_at=expires_at or (timezone.now() + timedelta(minutes=10)),
            is_active=True,
        )
        return plain

    def test_valid_machine_token_can_list_secrets_without_redirect(self):
        token = self._create_machine_token(environment=self.environment)
        response = self.client.get(
            "/secrets/list/?environment=test&folder=shaik",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["auth_type"], "machine_token")

    def test_missing_token_returns_json_401_for_api_request(self):
        response = self.client.get(
            "/secrets/list/?environment=test&folder=shaik",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_expired_token_returns_json_401(self):
        token = self._create_machine_token(environment=self.environment, expires_at=timezone.now() - timedelta(minutes=1))
        response = self.client.get(
            "/secrets/list/?environment=test&folder=shaik",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_token_without_read_returns_json_403(self):
        token = self._create_machine_token(can_read=False, environment=self.environment)
        response = self.client.get(
            "/secrets/list/?environment=test&folder=shaik",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")


class MachineTokenRevealSecretTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username="owner_reveal", email="owner_reveal@example.com", password="ownerpass")
        self.machine_user = User.objects.create_user(username="machine_reveal", email="machine_reveal@example.com", password="machinepass")
        self.environment = Environment.objects.create(name="prod", created_by=self.owner)
        self.folder = Folder.objects.create(name="apps", environment=self.environment, owner_email="svc@example.com")
        self.secret = Secret.objects.create(name="API_KEY", service_name="svc", encrypted_value=b"ciphertext", folder=self.folder)

    def _create_machine_token(self, *, can_read=True):
        access = AccessPolicy.objects.create(
            user=self.machine_user,
            environment=self.environment,
            can_read=can_read,
            can_write=False,
            can_delete=False,
        )
        machine_policy = MachinePolicy.objects.create(
            name=f"machine-reveal-policy-{MachinePolicy.objects.count()+1}",
            access_policy=access,
            created_by=self.owner,
        )
        plain = f"mvt_reveal_plain_{MachineSessionToken.objects.count()+1}"
        MachineSessionToken.objects.create(
            token_hash=dashboard_views.hashlib.sha256(plain.encode()).hexdigest(),
            machine_policy=machine_policy,
            expires_at=timezone.now() + timedelta(minutes=10),
            is_active=True,
        )
        return plain

    @patch("vault_dashboard.views.decrypt_value", return_value="super-secret")
    def test_valid_machine_token_can_reveal_secret_without_redirect(self, _mock_decrypt):
        token = self._create_machine_token(can_read=True)
        response = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertNotIn("Location", response)
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["secret"], "super-secret")
        self.assertEqual(body["auth_type"], "machine_token")

    def test_missing_or_invalid_token_returns_json_auth_errors(self):
        missing = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing["Content-Type"], "application/json")
        self.assertNotIn("Location", missing)

        invalid = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_AUTHORIZATION="Bearer mvt_invalid_token",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(invalid["Content-Type"], "application/json")
        self.assertNotIn("Location", invalid)
        self.assertEqual(invalid.json()["error"], "Invalid machine token.")

    def test_token_without_can_read_returns_403(self):
        token = self._create_machine_token(can_read=False)
        response = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_invalid_authorization_header_returns_json_401_not_redirect(self):
        response = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_AUTHORIZATION="Bearer invalid-format-token",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertNotIn("Location", response)

    def test_invalid_secret_id_returns_json_404(self):
        token = self._create_machine_token(can_read=True)
        response = self.client.get(
            "/secrets/reveal-secret/999999/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json()["error"], "Secret not found")

    @patch("vault_dashboard.views.decrypt_value", side_effect=Exception("decrypt failure"))
    def test_internal_error_returns_json_500_not_html(self, _mock_decrypt):
        token = self._create_machine_token(can_read=True)
        response = self.client.get(
            f"/secrets/reveal-secret/{self.secret.id}/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json()["error"], "decrypt failure")

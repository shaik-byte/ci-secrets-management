import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from cryptography.fernet import Fernet

from .models import AccessPolicy, Environment, Folder, Secret
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

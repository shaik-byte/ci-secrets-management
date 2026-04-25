import json
import hashlib
from unittest.mock import patch
from datetime import timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from cryptography.fernet import Fernet

from .models import AccessPolicy, Environment, Folder, Secret, MachinePolicy, JWTWorkloadIdentity, MachineSessionToken
from . import views as dashboard_views


class JwtLoginAliasRouteTests(TestCase):
    def test_auth_jwt_login_alias_rejects_non_post(self):
        response = self.client.get("/auth/jwt/login/")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["error"], "POST method required.")

    def test_auth_jwt_login_alias_accepts_same_payload_handling(self):
        response = self.client.post(
            "/auth/jwt/login/",
            data=json.dumps({"identity_name": "demo"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Field 'jwt' is required.")


class JwtMachineLoginDebugTests(TestCase):
    def _mint_rs256_token(self, claims: dict) -> str:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "kid-1"})

    def test_jwt_machine_login_rejects_non_rs256_algorithms(self):
        token = jwt.encode(
            {"iss": "https://issuer.example.com", "sub": "svc", "aud": "vault", "exp": 4102444800, "iat": 1700000000},
            "shared-secret",
            algorithm="HS256",
        )
        response = self.client.post(
            "/auth/jwt/login/",
            data=json.dumps({"jwt": token}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported JWT algorithm", response.json()["error"])

    def test_jwt_machine_login_returns_detailed_failure_reasons(self):
        user = User.objects.create_superuser(username="root", email="root@example.com", password="rootpass")
        access_policy = AccessPolicy.objects.create(user=user, can_read=True, can_write=False, can_delete=False)
        machine_policy = MachinePolicy.objects.create(
            name="mp-debug",
            description="debug",
            access_policy=access_policy,
            created_by=user,
        )
        JWTWorkloadIdentity.objects.create(
            name="debug-identity",
            issuer="https://issuer.example.com",
            audience="vault",
            subject_pattern="system:serviceaccount:*",
            jwks_url="https://issuer.example.com/.well-known/jwks.json",
            machine_policy=machine_policy,
            is_active=True,
        )
        token = self._mint_rs256_token(
            {
                "iss": "https://issuer.example.com",
                "sub": "user:local-dev",
                "aud": "vault",
                "exp": 4102444800,
                "iat": 1700000000,
            }
        )
        response = self.client.post(
            "/auth/jwt/login/",
            data=json.dumps({"jwt": token}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertEqual(payload["error"], "JWT verification failed for all matching identities.")
        self.assertTrue(payload.get("details"))
        self.assertIn("does not match pattern", payload["details"][0])


class MachineTokenSecretsApiTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(username="rootapi", email="rootapi@example.com", password="rootpass")
        self.environment = Environment.objects.create(name="test", created_by=self.owner)
        self.folder = Folder.objects.create(name="shaik", environment=self.environment, owner_email="rootapi@example.com")
        self.other_folder = Folder.objects.create(name="other", environment=self.environment, owner_email="rootapi@example.com")
        self.secret = Secret.objects.create(name="API_KEY", service_name="svc", encrypted_value=b"x", folder=self.folder)
        self.other_secret = Secret.objects.create(name="DB_PASS", service_name="svc", encrypted_value=b"y", folder=self.other_folder)

        self.access_policy = AccessPolicy.objects.create(
            user=self.owner,
            folder=self.folder,
            can_read=True,
            can_write=False,
            can_delete=False,
        )
        self.machine_policy = MachinePolicy.objects.create(
            name="api-read-only",
            description="Machine list",
            access_policy=self.access_policy,
            created_by=self.owner,
        )
        self.raw_machine_token = "mvt_test_machine_token_123"
        self.machine_session = MachineSessionToken.objects.create(
            token_hash=hashlib.sha256(self.raw_machine_token.encode()).hexdigest(),
            machine_policy=self.machine_policy,
            expires_at=timezone.now() + timedelta(hours=1),
            is_active=True,
        )

    def test_api_list_secrets_requires_bearer_token(self):
        response = self.client.get("/api/secrets/list/?environment=test&folder=shaik")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Authorization", response.json()["error"])

    def test_api_list_secrets_returns_json_for_valid_machine_token(self):
        response = self.client.get(
            "/api/secrets/list/?environment=test&folder=shaik",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_machine_token}",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["secrets"][0]["name"], "API_KEY")
        self.assertEqual(payload["machine_policy"], self.machine_policy.name)

    def test_api_list_secrets_rejects_expired_machine_token(self):
        self.machine_session.expires_at = timezone.now() - timedelta(minutes=1)
        self.machine_session.save(update_fields=["expires_at"])
        response = self.client.get(
            "/api/secrets/list/?environment=test&folder=shaik",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_machine_token}",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "Machine token expired.")

    def test_api_list_secrets_enforces_policy_scope(self):
        response = self.client.get(
            "/api/secrets/list/?environment=test&folder=other",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_machine_token}",
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("does not have read access", response.json()["error"])


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

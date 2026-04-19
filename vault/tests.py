import base64

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from auditlogs.models import AuditLog
from vault.crypto_utils import encrypt_root_key
from vault.models import VaultConfig


class LoginAuthenticationFlowTests(TestCase):
    def setUp(self):
        cache.set("vault_restart_seal_initialized", True, None)
        cache.set("vault_hard_sealed", False, None)
        self.root_key = b"0123456789ABCDEF"
        self.vault = VaultConfig.objects.create(
            encrypted_root_key=encrypt_root_key(self.root_key),
            allowed_location="LOCALHOST",
            is_sealed=False,
            total_shares=5,
            threshold=3,
        )
        self.user = User.objects.create_user(username="alice", password="alice-pass")
        self.superuser = User.objects.create_superuser(username="rootadmin", email="root@example.com", password="root-pass")

    def test_login_page_shows_both_authentication_methods(self):
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username / Password")
        self.assertContains(response, "Root Token")

    def test_username_password_login_works(self):
        response = self.client.post(
            reverse("login"),
            {
                "auth_method": "username_password",
                "username": "alice",
                "password": "alice-pass",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("vault_dashboard"))
        self.assertIn("_auth_user_id", self.client.session)

    def test_root_token_login_works(self):
        token = base64.b64encode(self.root_key).decode()
        response = self.client.post(
            reverse("login"),
            {
                "auth_method": "root_token",
                "root_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("vault_dashboard"))
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.superuser.id))
        self.assertEqual(self.client.session.get("vault_key"), token)

    def test_invalid_root_token_shows_error(self):
        invalid_b64_token = base64.b64encode(b"wrong-root-key-1").decode()
        response = self.client.post(
            reverse("login"),
            {
                "auth_method": "root_token",
                "root_token": invalid_b64_token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid root token.")

    def test_cli_login_writes_audit_log(self):
        response = self.client.post(
            reverse("cli_login"),
            data={
                "auth_method": "username_password",
                "username": "alice",
                "password": "alice-pass",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("ok"))

        log = AuditLog.objects.filter(user=self.user, action="LOGIN", entity="CLI").order_by("-timestamp").first()
        self.assertIsNotNone(log)
        self.assertIn("Authenticated via username_password", log.details or "")

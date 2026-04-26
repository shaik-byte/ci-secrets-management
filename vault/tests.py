import re

from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vault.models import VaultConfig
from vault_dashboard.models import AccessPolicy, Environment, Folder, Secret


class VaultBootstrapFlowTests(TestCase):
    def _initialize_vault(self, total_shares=5, threshold=3):
        response = self.client.post(
            reverse("initialize"),
            {"total_shares": total_shares, "threshold": threshold},
        )
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        shares = re.findall(r"<code>(\d+-[0-9a-f]+)</code>", html)
        root_match = re.search(r"<code>([A-Za-z0-9_\-]{40,})</code>", html)
        self.assertIsNotNone(root_match)
        return shares, root_match.group(1)

    def _unseal_with_shares(self, shares, threshold=3):
        for share in shares[:threshold]:
            response = self.client.post(reverse("unseal"), {"share": share})
        return response

    def test_initialize_only_works_once(self):
        self._initialize_vault()
        response = self.client.post(reverse("initialize"), {"total_shares": 5, "threshold": 3})
        self.assertEqual(response.status_code, 302)

    def test_root_token_is_hashed(self):
        _, root_token = self._initialize_vault()
        vault = VaultConfig.objects.first()
        self.assertNotEqual(vault.root_token_hash, root_token)
        self.assertTrue(check_password(root_token, vault.root_token_hash))

    def test_unseal_requires_threshold_shares(self):
        shares, _ = self._initialize_vault(total_shares=5, threshold=3)
        self.client.post(reverse("unseal"), {"share": shares[0]})
        self.client.post(reverse("unseal"), {"share": shares[1]})
        vault = VaultConfig.objects.first()
        self.assertTrue(vault.sealed)

    def test_invalid_shares_fail(self):
        shares, _ = self._initialize_vault(total_shares=5, threshold=3)
        bad_share = "99-" + ("aa" * 16)
        self.client.post(reverse("unseal"), {"share": shares[0]})
        self.client.post(reverse("unseal"), {"share": shares[1]})
        response = self.client.post(reverse("unseal"), {"share": bad_share})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Submitted shares are not valid")

    def test_sealed_vault_blocks_secret_read_write(self):
        user = User.objects.create_user(username="alice", password="pass12345")
        self.client.force_login(user)
        env = Environment.objects.create(name="prod", created_by=user)
        folder = Folder.objects.create(name="api", environment=env)
        secret = Secret.objects.create(name="token", encrypted_value=b"cipher", folder=folder)

        add_resp = self.client.post(reverse("add_secret", kwargs={"folder_id": folder.id}), {"name": "x", "value": "y"})
        reveal_resp = self.client.get(reverse("reveal_secret", kwargs={"secret_id": secret.id}))

        self.assertEqual(add_resp.status_code, 403)
        self.assertEqual(reveal_resp.status_code, 403)

    def test_root_can_create_users_after_login(self):
        shares, root_token = self._initialize_vault(total_shares=5, threshold=3)
        self._unseal_with_shares(shares, threshold=3)

        login_resp = self.client.post(reverse("root_token_login"), {"root_token": root_token})
        self.assertEqual(login_resp.status_code, 302)

        create_resp = self.client.post(
            reverse("root_create_user"),
            {"username": "svc-reader", "password": "StrongPass123!", "policy_name": "read-only"},
        )
        self.assertEqual(create_resp.status_code, 200)
        self.assertTrue(User.objects.filter(username="svc-reader").exists())
        policy = AccessPolicy.objects.filter(user__username="svc-reader").first()
        self.assertIsNotNone(policy)
        self.assertTrue(policy.can_read)
        self.assertFalse(policy.can_write)
        self.assertFalse(policy.can_delete)

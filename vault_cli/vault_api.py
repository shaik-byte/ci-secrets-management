from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class VaultSession:
    server_url: str
    token: str

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self.token}

    def read_secret(self, path: str) -> dict[str, Any]:
        response = requests.get(f"{self.server_url}/v1/{path}", headers=self._headers(), timeout=20)
        response.raise_for_status()
        return response.json()

    def write_secret(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            f"{self.server_url}/v1/{path}", json=data, headers=self._headers(), timeout=20
        )
        response.raise_for_status()
        return response.json() if response.text else {}

    def list_paths(self, path: str) -> dict[str, Any]:
        response = requests.request(
            "LIST",
            f"{self.server_url}/v1/{path}",
            headers=self._headers(),
            timeout=20,
        )
        if response.status_code == 405:
            response = requests.get(
                f"{self.server_url}/v1/{path}?list=true",
                headers=self._headers(),
                timeout=20,
            )
        response.raise_for_status()
        return response.json()

    def delete_secret(self, path: str) -> None:
        response = requests.delete(f"{self.server_url}/v1/{path}", headers=self._headers(), timeout=20)
        response.raise_for_status()


def authenticate(
    server_url: str,
    auth_method: str,
    credentials: dict[str, str],
    auth_mount: str,
) -> VaultSession:
    server_url = server_url.rstrip("/")

    if auth_method == "token":
        token = credentials.get("token")
        if not token:
            raise ValueError("Missing token credential.")
        return VaultSession(server_url=server_url, token=token)

    if auth_method == "approle":
        payload = {
            "role_id": credentials.get("role_id"),
            "secret_id": credentials.get("secret_id"),
        }
        response = requests.post(
            f"{server_url}/v1/auth/{auth_mount}/login",
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        token = response.json().get("auth", {}).get("client_token")
        if not token:
            raise ValueError("Vault did not return a client token for AppRole authentication.")
        return VaultSession(server_url=server_url, token=token)

    if auth_method == "userpass":
        username = credentials.get("username")
        password = credentials.get("password")
        if not username or not password:
            raise ValueError("Missing username/password credentials.")
        response = requests.post(
            f"{server_url}/v1/auth/{auth_mount}/login/{username}",
            json={"password": password},
            timeout=20,
        )
        response.raise_for_status()
        token = response.json().get("auth", {}).get("client_token")
        if not token:
            raise ValueError("Vault did not return a client token for userpass authentication.")
        return VaultSession(server_url=server_url, token=token)

    raise ValueError(f"Unsupported auth method: {auth_method}")

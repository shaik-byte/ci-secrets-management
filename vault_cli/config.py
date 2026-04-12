from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover
    keyring = None


CONFIG_DIR = Path.home() / ".vaultcli"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEY_FILE = CONFIG_DIR / "key.bin"
CREDS_FILE = CONFIG_DIR / "credentials.enc"
KEYRING_SERVICE = "vaultcli"


@dataclass
class Profile:
    name: str
    server_url: str
    auth_method: str
    auth_mount: str


class ConfigStore:
    def __init__(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CONFIG_DIR, 0o700)

    def _read_config(self) -> dict[str, Any]:
        if not CONFIG_FILE.exists():
            return {"active_profile": None, "profiles": {}}
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    def _write_config(self, data: dict[str, Any]) -> None:
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(CONFIG_FILE, 0o600)

    def list_profiles(self) -> list[Profile]:
        cfg = self._read_config()
        profiles = []
        for name, p in cfg.get("profiles", {}).items():
            profiles.append(
                Profile(
                    name=name,
                    server_url=p["server_url"],
                    auth_method=p["auth_method"],
                    auth_mount=p.get("auth_mount", ""),
                )
            )
        return sorted(profiles, key=lambda p: p.name)

    def get_profile(self, name: str) -> Profile | None:
        cfg = self._read_config()
        p = cfg.get("profiles", {}).get(name)
        if not p:
            return None
        return Profile(
            name=name,
            server_url=p["server_url"],
            auth_method=p["auth_method"],
            auth_mount=p.get("auth_mount", ""),
        )

    def get_active_profile(self) -> Profile:
        cfg = self._read_config()
        active = cfg.get("active_profile")
        if not active:
            raise ValueError("No active profile configured. Run `vaultcli configure` first.")
        profile = self.get_profile(active)
        if not profile:
            raise ValueError(f"Active profile '{active}' not found.")
        return profile

    def set_active_profile(self, name: str) -> None:
        cfg = self._read_config()
        if name not in cfg.get("profiles", {}):
            raise ValueError(f"Profile '{name}' does not exist.")
        cfg["active_profile"] = name
        self._write_config(cfg)

    def save_profile(self, profile: Profile) -> None:
        cfg = self._read_config()
        cfg.setdefault("profiles", {})[profile.name] = {
            "server_url": profile.server_url.rstrip("/"),
            "auth_method": profile.auth_method,
            "auth_mount": profile.auth_mount,
        }
        if not cfg.get("active_profile"):
            cfg["active_profile"] = profile.name
        self._write_config(cfg)

    def delete_profile(self, name: str) -> None:
        cfg = self._read_config()
        if name not in cfg.get("profiles", {}):
            raise ValueError(f"Profile '{name}' not found.")
        del cfg["profiles"][name]
        if cfg.get("active_profile") == name:
            cfg["active_profile"] = next(iter(cfg["profiles"].keys()), None)
        self._write_config(cfg)
        self.delete_credentials(name)

    def _load_or_create_key(self) -> bytes:
        if KEY_FILE.exists():
            return KEY_FILE.read_bytes()
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        os.chmod(KEY_FILE, 0o600)
        return key

    def _read_encrypted_credentials(self) -> dict[str, Any]:
        if not CREDS_FILE.exists():
            return {}
        key = self._load_or_create_key()
        fernet = Fernet(key)
        raw = CREDS_FILE.read_bytes()
        decrypted = fernet.decrypt(raw)
        return json.loads(decrypted.decode("utf-8"))

    def _write_encrypted_credentials(self, payload: dict[str, Any]) -> None:
        key = self._load_or_create_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(json.dumps(payload).encode("utf-8"))
        CREDS_FILE.write_bytes(encrypted)
        os.chmod(CREDS_FILE, 0o600)

    def save_credentials(self, profile_name: str, credentials: dict[str, str]) -> None:
        if keyring:
            keyring.set_password(KEYRING_SERVICE, profile_name, json.dumps(credentials))
            return
        payload = self._read_encrypted_credentials()
        payload[profile_name] = credentials
        self._write_encrypted_credentials(payload)

    def get_credentials(self, profile_name: str) -> dict[str, str]:
        if keyring:
            raw = keyring.get_password(KEYRING_SERVICE, profile_name)
            if not raw:
                raise ValueError(f"Credentials for profile '{profile_name}' not found.")
            return json.loads(raw)
        payload = self._read_encrypted_credentials()
        creds = payload.get(profile_name)
        if not creds:
            raise ValueError(f"Credentials for profile '{profile_name}' not found.")
        return creds

    def delete_credentials(self, profile_name: str) -> None:
        if keyring:
            try:
                keyring.delete_password(KEYRING_SERVICE, profile_name)
            except Exception:
                pass
            return
        payload = self._read_encrypted_credentials()
        if profile_name in payload:
            del payload[profile_name]
            self._write_encrypted_credentials(payload)

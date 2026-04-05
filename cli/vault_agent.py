#!/usr/bin/env python3
"""Vault CLI agent for secret operations.

Usage examples:
  python cli/vault_agent.py login --root-token <token>
  python cli/vault_agent.py list-secrets --environment prod --folder payments
  python cli/vault_agent.py add-secret --environment prod --folder payments --name API_KEY --value supersecret
  python cli/vault_agent.py delete-secret --environment prod --folder payments --name API_KEY
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import django
from cryptography.fernet import Fernet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.conf import settings  # noqa: E402
from django.core.exceptions import ObjectDoesNotExist  # noqa: E402

from vault.crypto_utils import decrypt_root_key  # noqa: E402
from vault.models import VaultConfig  # noqa: E402
from django.contrib.auth.models import User  # noqa: E402
from vault_dashboard.models import AccessPolicy, Environment, Folder, Secret  # noqa: E402


SESSION_FILE = Path.home() / ".vault_cli_session.json"


class AuthError(Exception):
    pass


@dataclass
class AuthContext:
    root_key: bytes


def _load_token_from_session() -> Optional[str]:
    if not SESSION_FILE.exists():
        return None
    try:
        payload = json.loads(SESSION_FILE.read_text())
        return payload.get("root_token")
    except Exception:
        return None


def _save_token_to_session(root_token: str) -> None:
    SESSION_FILE.write_text(json.dumps({"root_token": root_token}))
    SESSION_FILE.chmod(0o600)


def _resolve_token(explicit_token: Optional[str]) -> str:
    token = explicit_token or os.getenv("VAULT_ROOT_TOKEN") or _load_token_from_session()
    if not token:
        raise AuthError(
            "No root token provided. Use --root-token, or set VAULT_ROOT_TOKEN, "
            "or run `login` first."
        )
    return token


def _validate_and_get_root_key(root_token: str) -> bytes:
    vault = VaultConfig.objects.first()
    if not vault:
        raise AuthError("Vault is not initialized (VaultConfig is missing).")

    decrypted_root_key = decrypt_root_key(vault.encrypted_root_key)

    # Accept KEK directly (operator token) OR the actual root key in base64.
    if root_token == settings.VAULT_KEK:
        return decrypted_root_key

    try:
        token_bytes = base64.urlsafe_b64decode(root_token.encode())
        if token_bytes == decrypted_root_key:
            return decrypted_root_key
    except Exception:
        pass

    raise AuthError(
        "Authentication failed. Provide either settings.VAULT_KEK or the base64 root key token."
    )


def _fernet_from_root_key(root_key: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(root_key[:32]))


def _get_folder(environment_name: str, folder_name: str) -> Folder:
    try:
        env = Environment.objects.get(name=environment_name)
    except ObjectDoesNotExist as exc:
        raise ValueError(f"Environment '{environment_name}' not found.") from exc

    try:
        return Folder.objects.get(name=folder_name, environment=env)
    except ObjectDoesNotExist as exc:
        raise ValueError(
            f"Folder '{folder_name}' not found in environment '{environment_name}'."
        ) from exc


def cmd_login(args: argparse.Namespace) -> int:
    token = _resolve_token(args.root_token)
    _validate_and_get_root_key(token)
    _save_token_to_session(token)
    print(f"Authenticated. Session saved to {SESSION_FILE}")
    return 0


def cmd_logout(_: argparse.Namespace) -> int:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
        print("Logged out. Local session removed.")
    else:
        print("No local session was found.")
    return 0


def _auth_context(args: argparse.Namespace) -> AuthContext:
    token = _resolve_token(args.root_token)
    root_key = _validate_and_get_root_key(token)
    return AuthContext(root_key=root_key)


def cmd_list_secrets(args: argparse.Namespace) -> int:
    auth = _auth_context(args)
    fernet = _fernet_from_root_key(auth.root_key)

    folder = _get_folder(args.environment, args.folder)
    secrets = Secret.objects.filter(folder=folder).order_by("id")

    if not secrets.exists():
        print("No secrets found.")
        return 0

    print(f"Secrets for {args.environment}/{args.folder} (owner={folder.owner_email or '-' }):")
    for secret in secrets:
        row = [f"- id={secret.id}", f"name={secret.name}"]
        if args.show_values:
            value = fernet.decrypt(secret.encrypted_value).decode()
            row.append(f"value={value}")
        if secret.service_name:
            row.append(f"service={secret.service_name}")
        if secret.expire_date:
            row.append(f"expire={secret.expire_date.isoformat()}")
        print(" | ".join(row))

    return 0


def cmd_add_secret(args: argparse.Namespace) -> int:
    auth = _auth_context(args)
    fernet = _fernet_from_root_key(auth.root_key)

    folder = _get_folder(args.environment, args.folder)

    expire_date = None
    if args.expire_date:
        expire_date = datetime.strptime(args.expire_date, "%Y-%m-%d").date()

    secret = Secret.objects.create(
        name=args.name,
        encrypted_value=fernet.encrypt(args.value.encode()),
        service_name=args.service_name or "",
        expire_date=expire_date,
        folder=folder,
    )

    print(
        f"Secret created: id={secret.id}, name={secret.name}, "
        f"location={args.environment}/{args.folder}"
    )
    return 0


def cmd_delete_secret(args: argparse.Namespace) -> int:
    _auth_context(args)
    folder = _get_folder(args.environment, args.folder)

    queryset = Secret.objects.filter(folder=folder)
    if args.id is not None:
        queryset = queryset.filter(id=args.id)
    else:
        queryset = queryset.filter(name=args.name)

    secret = queryset.first()
    if not secret:
        if args.id is not None:
            raise ValueError(
                f"Secret with id={args.id} not found in {args.environment}/{args.folder}."
            )
        raise ValueError(
            f"Secret named '{args.name}' not found in {args.environment}/{args.folder}."
        )

    sid = secret.id
    sname = secret.name
    secret.delete()
    print(f"Deleted secret: id={sid}, name={sname}")
    return 0


def _resolve_user(username: str) -> User:
    try:
        return User.objects.get(username=username)
    except ObjectDoesNotExist as exc:
        raise ValueError(f"User '{username}' not found.") from exc


def _resolve_scope(
    environment_name: Optional[str],
    folder_name: Optional[str],
    secret_name: Optional[str],
) -> tuple[Optional[Environment], Optional[Folder], Optional[Secret]]:
    environment = None
    folder = None
    secret = None

    if environment_name:
        try:
            environment = Environment.objects.get(name=environment_name)
        except ObjectDoesNotExist as exc:
            raise ValueError(f"Environment '{environment_name}' not found.") from exc

    if folder_name:
        if not environment:
            raise ValueError("--folder requires --environment.")
        try:
            folder = Folder.objects.get(name=folder_name, environment=environment)
        except ObjectDoesNotExist as exc:
            raise ValueError(
                f"Folder '{folder_name}' not found in environment '{environment_name}'."
            ) from exc

    if secret_name:
        if not folder:
            raise ValueError("--secret requires both --environment and --folder.")
        try:
            secret = Secret.objects.get(name=secret_name, folder=folder)
        except ObjectDoesNotExist as exc:
            raise ValueError(
                f"Secret '{secret_name}' not found in {environment_name}/{folder_name}."
            ) from exc

    return environment, folder, secret


def cmd_policy_list(args: argparse.Namespace) -> int:
    _auth_context(args)

    queryset = AccessPolicy.objects.select_related(
        "user", "environment", "folder", "secret"
    ).order_by("id")
    if args.user:
        queryset = queryset.filter(user__username=args.user)

    if not queryset.exists():
        print("No access policies found.")
        return 0

    for policy in queryset:
        scope = "global"
        if policy.secret_id:
            scope = (
                f"{policy.secret.folder.environment.name}/"
                f"{policy.secret.folder.name}/{policy.secret.name}"
            )
        elif policy.folder_id:
            scope = f"{policy.folder.environment.name}/{policy.folder.name}"
        elif policy.environment_id:
            scope = f"{policy.environment.name}"

        print(
            f"- id={policy.id} | user={policy.user.username} | scope={scope} | "
            f"read={policy.can_read} write={policy.can_write} delete={policy.can_delete}"
        )
    return 0


def cmd_policy_save(args: argparse.Namespace) -> int:
    _auth_context(args)

    user = _resolve_user(args.user)
    environment, folder, secret = _resolve_scope(args.environment, args.folder, args.secret)

    if not any([args.can_read, args.can_write, args.can_delete]):
        raise ValueError("Provide at least one permission flag: --read, --write, or --delete.")

    policy, _ = AccessPolicy.objects.update_or_create(
        user=user,
        environment=environment,
        folder=folder,
        secret=secret,
        defaults={
            "can_read": args.can_read,
            "can_write": args.can_write,
            "can_delete": args.can_delete,
        },
    )
    print(
        f"Policy saved: id={policy.id} user={user.username} "
        f"read={policy.can_read} write={policy.can_write} delete={policy.can_delete}"
    )
    return 0


def cmd_policy_delete(args: argparse.Namespace) -> int:
    _auth_context(args)

    if args.policy_id is not None:
        policy = AccessPolicy.objects.filter(id=args.policy_id).first()
        if not policy:
            raise ValueError(f"Policy id={args.policy_id} not found.")
        policy.delete()
        print(f"Policy deleted: id={args.policy_id}")
        return 0

    user = _resolve_user(args.user)
    environment, folder, secret = _resolve_scope(args.environment, args.folder, args.secret)
    policy = AccessPolicy.objects.filter(
        user=user,
        environment=environment,
        folder=folder,
        secret=secret,
    ).first()
    if not policy:
        raise ValueError("Matching policy not found for provided user/scope.")
    pid = policy.id
    policy.delete()
    print(f"Policy deleted: id={pid}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vault CLI Agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login", help="Authenticate and save local CLI session")
    login.add_argument("--root-token", required=False, help="VAULT_KEK or base64 root key token")
    login.set_defaults(func=cmd_login)

    logout = subparsers.add_parser("logout", help="Remove local CLI session")
    logout.set_defaults(func=cmd_logout)

    list_cmd = subparsers.add_parser("list-secrets", help="List secrets by environment and folder")
    list_cmd.add_argument("--root-token", required=False, help="Override token for this call")
    list_cmd.add_argument("--environment", required=True, help="Environment name")
    list_cmd.add_argument("--folder", required=True, help="Folder name")
    list_cmd.add_argument(
        "--show-values",
        action="store_true",
        help="Decrypt and display secret values",
    )
    list_cmd.set_defaults(func=cmd_list_secrets)

    add_cmd = subparsers.add_parser("add-secret", help="Create a secret in a folder")
    add_cmd.add_argument("--root-token", required=False, help="Override token for this call")
    add_cmd.add_argument("--environment", required=True, help="Environment name")
    add_cmd.add_argument("--folder", required=True, help="Folder name")
    add_cmd.add_argument("--name", required=True, help="Secret name")
    add_cmd.add_argument("--value", required=True, help="Secret plaintext value")
    add_cmd.add_argument("--service-name", required=False, default="", help="Optional service name")
    add_cmd.add_argument(
        "--expire-date",
        required=False,
        help="Optional expiry date in YYYY-MM-DD format",
    )
    add_cmd.set_defaults(func=cmd_add_secret)

    del_cmd = subparsers.add_parser("delete-secret", help="Delete a secret by id or name")
    del_cmd.add_argument("--root-token", required=False, help="Override token for this call")
    del_cmd.add_argument("--environment", required=True, help="Environment name")
    del_cmd.add_argument("--folder", required=True, help="Folder name")
    identity = del_cmd.add_mutually_exclusive_group(required=True)
    identity.add_argument("--id", type=int, help="Secret id")
    identity.add_argument("--name", help="Secret name")
    del_cmd.set_defaults(func=cmd_delete_secret)

    policy_list = subparsers.add_parser(
        "policy-list", help="List policy engine access policies (CLI)"
    )
    policy_list.add_argument("--root-token", required=False, help="Override token for this call")
    policy_list.add_argument("--user", required=False, help="Filter by username")
    policy_list.set_defaults(func=cmd_policy_list)

    policy_save = subparsers.add_parser(
        "policy-save", help="Create/update an access policy (CLI)"
    )
    policy_save.add_argument("--root-token", required=False, help="Override token for this call")
    policy_save.add_argument("--user", required=True, help="Username to bind policy")
    policy_save.add_argument("--environment", required=False, help="Environment name")
    policy_save.add_argument("--folder", required=False, help="Folder name (requires --environment)")
    policy_save.add_argument("--secret", required=False, help="Secret name (requires --environment and --folder)")
    policy_save.add_argument("--read", dest="can_read", action="store_true", help="Grant read")
    policy_save.add_argument("--write", dest="can_write", action="store_true", help="Grant write")
    policy_save.add_argument("--delete", dest="can_delete", action="store_true", help="Grant delete")
    policy_save.set_defaults(func=cmd_policy_save)

    policy_delete = subparsers.add_parser(
        "policy-delete", help="Delete access policy by id or by user/scope (CLI)"
    )
    policy_delete.add_argument("--root-token", required=False, help="Override token for this call")
    policy_delete.add_argument("--policy-id", type=int, required=False, help="Policy id")
    policy_delete.add_argument("--user", required=False, help="Username (required when --policy-id not provided)")
    policy_delete.add_argument("--environment", required=False, help="Environment name")
    policy_delete.add_argument("--folder", required=False, help="Folder name")
    policy_delete.add_argument("--secret", required=False, help="Secret name")
    policy_delete.set_defaults(func=cmd_policy_delete)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "policy-delete" and args.policy_id is None and not args.user:
            raise ValueError("policy-delete requires --policy-id or --user.")
        return args.func(args)
    except (AuthError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

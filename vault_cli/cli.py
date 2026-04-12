from __future__ import annotations

import argparse
import getpass
import json
from typing import Any

from .config import ConfigStore, Profile
from .vault_api import authenticate


def _parse_kv_pairs(values: list[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Invalid key/value '{value}'. Use key=value.")
        key, val = value.split("=", 1)
        output[key] = val
    return output


def cmd_configure(args: argparse.Namespace, store: ConfigStore) -> int:
    auth_mount = args.auth_mount or ("approle" if args.auth_method == "approle" else "userpass")
    profile = Profile(
        name=args.profile,
        server_url=args.server_url,
        auth_method=args.auth_method,
        auth_mount=auth_mount,
    )

    creds: dict[str, str]
    if args.auth_method == "token":
        token = args.token or getpass.getpass("Vault token: ")
        creds = {"token": token}
    elif args.auth_method == "approle":
        role_id = args.role_id or input("AppRole role_id: ").strip()
        secret_id = args.secret_id or getpass.getpass("AppRole secret_id: ")
        creds = {"role_id": role_id, "secret_id": secret_id}
    else:
        username = args.username or input("Username: ").strip()
        password = args.password or getpass.getpass("Password: ")
        creds = {"username": username, "password": password}

    store.save_profile(profile)
    store.save_credentials(args.profile, creds)
    store.set_active_profile(args.profile)
    print(f"Profile '{args.profile}' configured and set active.")
    return 0


def _session_from_profile(store: ConfigStore, profile_name: str | None):
    profile = store.get_profile(profile_name) if profile_name else store.get_active_profile()
    if not profile:
        raise ValueError(f"Profile '{profile_name}' was not found.")

    creds = store.get_credentials(profile.name)
    return authenticate(
        server_url=profile.server_url,
        auth_method=profile.auth_method,
        credentials=creds,
        auth_mount=profile.auth_mount,
    )


def cmd_profiles(args: argparse.Namespace, store: ConfigStore) -> int:
    if args.action == "list":
        active_name = None
        try:
            active_name = store.get_active_profile().name
        except Exception:
            pass
        profiles = store.list_profiles()
        if not profiles:
            print("No profiles configured.")
            return 0
        for p in profiles:
            marker = "*" if p.name == active_name else " "
            print(f"{marker} {p.name} | {p.server_url} | auth={p.auth_method} | mount={p.auth_mount}")
        return 0

    if args.action == "use":
        store.set_active_profile(args.profile)
        print(f"Active profile set to '{args.profile}'.")
        return 0

    if args.action == "delete":
        store.delete_profile(args.profile)
        print(f"Deleted profile '{args.profile}'.")
        return 0

    raise ValueError(f"Unsupported profiles action: {args.action}")


def cmd_read(args: argparse.Namespace, store: ConfigStore) -> int:
    session = _session_from_profile(store, args.profile)
    result = session.read_secret(args.path)
    if args.field:
        print(result.get("data", {}).get(args.field, ""))
    else:
        print(json.dumps(result, indent=2))
    return 0


def cmd_write(args: argparse.Namespace, store: ConfigStore) -> int:
    session = _session_from_profile(store, args.profile)
    payload = _parse_kv_pairs(args.data)
    result = session.write_secret(args.path, payload)
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("Write successful.")
    return 0


def cmd_list(args: argparse.Namespace, store: ConfigStore) -> int:
    session = _session_from_profile(store, args.profile)
    result = session.list_paths(args.path)
    print(json.dumps(result, indent=2))
    return 0


def cmd_delete(args: argparse.Namespace, store: ConfigStore) -> int:
    session = _session_from_profile(store, args.profile)
    session.delete_secret(args.path)
    print("Delete successful.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultcli", description="Multi-environment Vault CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    configure = sub.add_parser("configure", help="Configure a Vault environment profile")
    configure.add_argument("--profile", required=True)
    configure.add_argument("--server-url", required=True)
    configure.add_argument("--auth-method", choices=["token", "approle", "userpass"], required=True)
    configure.add_argument("--auth-mount", help="Auth mount name (default: approle/userpass)")
    configure.add_argument("--token")
    configure.add_argument("--role-id")
    configure.add_argument("--secret-id")
    configure.add_argument("--username")
    configure.add_argument("--password")

    profiles = sub.add_parser("profiles", help="Manage profiles")
    profiles_sub = profiles.add_subparsers(dest="action", required=True)
    profiles_sub.add_parser("list", help="List profiles")
    p_use = profiles_sub.add_parser("use", help="Set active profile")
    p_use.add_argument("profile")
    p_del = profiles_sub.add_parser("delete", help="Delete a profile")
    p_del.add_argument("profile")

    read = sub.add_parser("read", help="Read a secret path")
    read.add_argument("path")
    read.add_argument("--field")
    read.add_argument("--profile")

    write = sub.add_parser("write", help="Write key=value pairs to a secret path")
    write.add_argument("path")
    write.add_argument("data", nargs="+")
    write.add_argument("--profile")

    list_cmd = sub.add_parser("list", help="List keys in a path")
    list_cmd.add_argument("path")
    list_cmd.add_argument("--profile")

    delete = sub.add_parser("delete", help="Delete a secret path")
    delete.add_argument("path")
    delete.add_argument("--profile")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = ConfigStore()

    try:
        if args.command == "configure":
            return cmd_configure(args, store)
        if args.command == "profiles":
            return cmd_profiles(args, store)
        if args.command == "read":
            return cmd_read(args, store)
        if args.command == "write":
            return cmd_write(args, store)
        if args.command == "list":
            return cmd_list(args, store)
        if args.command == "delete":
            return cmd_delete(args, store)
        raise ValueError(f"Unknown command: {args.command}")
    except Exception as exc:
        print(f"Error: {exc}")
        return 1

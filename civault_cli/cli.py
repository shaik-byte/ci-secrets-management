#!/usr/bin/env python3
"""civault CLI client.

Configure once, then authenticate and manage secrets remotely.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import requests

APP_NAME = "civault"
CONFIG_DIR = Path.home() / ".civault"
CONFIG_FILE = CONFIG_DIR / "config.json"
SESSION_FILE = CONFIG_DIR / "session.json"


class CliError(Exception):
    pass


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _ensure_dir()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _get_config() -> dict[str, Any]:
    return _read_json(CONFIG_FILE)


def _set_config(url: str) -> None:
    normalized = url.strip().rstrip("/")
    if not normalized.startswith(("http://", "https://")):
        raise CliError("URL must start with http:// or https://")
    _write_json(CONFIG_FILE, {"vault_name": APP_NAME, "url": normalized})


def _load_session() -> requests.Session:
    session = requests.Session()
    payload = _read_json(SESSION_FILE)
    cookies = payload.get("cookies") or {}
    for key, value in cookies.items():
        session.cookies.set(key, value)
    return session


def _save_session(session: requests.Session) -> None:
    cookies = requests.utils.dict_from_cookiejar(session.cookies)
    _write_json(SESSION_FILE, {"cookies": cookies})


def _base_url(args: argparse.Namespace) -> str:
    config = _get_config()
    url = (args.url or config.get("url") or "").strip().rstrip("/")
    if not url:
        raise CliError("Vault URL is not configured. Run `civault configure --url <VAULT_URL>` first.")
    return url


def _extract_error(response: requests.Response) -> str:
    try:
        payload = response.json()
        return payload.get("error") or payload.get("detail") or response.text
    except Exception:
        return response.text


def _probe_auth(session: requests.Session, base_url: str) -> tuple[bool, str, dict[str, Any]]:
    """Check whether the current session is authenticated.

    Returns:
        (is_authenticated, mode, details)
        mode:
            - "cli_api": CLI endpoints are available and authenticated.
            - "legacy_ui": Authenticated against UI, but CLI API endpoints are missing.
            - "unauthenticated": Session is not authenticated.
    """
    ping = session.get(f"{base_url}/secrets/cli/ping/", timeout=20, allow_redirects=False)
    if ping.status_code == 200:
        try:
            return True, "cli_api", ping.json()
        except Exception:
            return True, "cli_api", {}

    if ping.status_code == 404:
        # Backward-compatibility fallback for servers running a branch
        # that does not include the dedicated CLI API routes yet.
        ui_probe = session.get(f"{base_url}/secrets/", timeout=20, allow_redirects=False)
        location = (ui_probe.headers.get("Location") or "").lower()
        redirected_to_login = ui_probe.status_code in {301, 302, 303, 307, 308} and "/login" in location
        if ui_probe.status_code == 200 or (
            ui_probe.status_code in {301, 302, 303, 307, 308} and not redirected_to_login
        ):
            return True, "legacy_ui", {}

    return False, "unauthenticated", {}


def cmd_configure(args: argparse.Namespace) -> int:
    _set_config(args.url)
    print(f"Configured vault '{APP_NAME}' URL: {args.url.rstrip('/')}")
    print(f"Config file: {CONFIG_FILE}")
    return 0


def cmd_show_config(_: argparse.Namespace) -> int:
    config = _get_config()
    if not config:
        print("No civault configuration found.")
        return 0
    print(json.dumps(config, indent=2))
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    base_url = _base_url(args)
    session = requests.Session()

    payload: dict[str, str]
    if args.root_token:
        payload = {"auth_method": "root_token", "root_token": args.root_token}
    else:
        if not args.username or not args.password:
            raise CliError("Provide --root-token OR both --username and --password.")
        payload = {
            "auth_method": "username_password",
            "username": args.username,
            "password": args.password,
        }

    cli_login_url = f"{base_url}/login/cli/"
    response = session.post(cli_login_url, json=payload, timeout=20, allow_redirects=False)
    if response.status_code == 404:
        login_url = f"{base_url}/login/"
        pre = session.get(login_url, timeout=20)
        pre.raise_for_status()

        csrf_token = session.cookies.get("csrftoken", "")
        headers = {"Referer": login_url}
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token

        response = session.post(login_url, data=payload, headers=headers, timeout=20, allow_redirects=True)
        response.raise_for_status()
    elif response.status_code != 200:
        raise CliError(f"Login failed: {_extract_error(response)}")

    authed, mode, details = _probe_auth(session, base_url)
    if not authed:
        raise CliError("Login failed. Verify credentials and that the vault is unsealed.")

    _save_session(session)
    user = details.get("user", "unknown")
    if mode == "legacy_ui":
        print(
            "Authenticated to civault UI, but CLI API routes are not available on this server branch yet."
        )
        print("Tip: run the server from the CLI-enabled branch to use secret management commands.")
    print(f"Authenticated to {APP_NAME} as '{user}'. Session saved: {SESSION_FILE}")
    return 0


def cmd_logout(_: argparse.Namespace) -> int:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    print("Logged out from civault CLI session.")
    return 0


def _authed_session(args: argparse.Namespace) -> tuple[str, requests.Session]:
    base_url = _base_url(args)
    session = _load_session()
    authed, mode, _ = _probe_auth(session, base_url)
    if not authed:
        raise CliError("Not authenticated. Run `civault login` first.")
    if mode != "cli_api":
        raise CliError(
            "Authenticated session found, but CLI API routes are unavailable on this server branch."
        )
    return base_url, session


def cmd_status(args: argparse.Namespace) -> int:
    base_url, session = _authed_session(args)
    ping = session.get(f"{base_url}/secrets/cli/ping/", timeout=20)
    payload = ping.json()
    print(
        f"Connected to {payload.get('vault', APP_NAME)} at {base_url} as {payload.get('user')} "
        f"(superuser={payload.get('is_superuser')})."
    )
    return 0


def cmd_list_secrets(args: argparse.Namespace) -> int:
    base_url, session = _authed_session(args)
    params = {
        "environment": args.environment,
        "folder": args.folder,
        "show_values": "true" if args.show_values else "false",
    }
    response = session.get(f"{base_url}/secrets/cli/secrets/", params=params, timeout=20)
    if response.status_code != 200:
        raise CliError(f"List failed: {_extract_error(response)}")

    payload = response.json()
    print(f"Secrets in {args.environment}/{args.folder}: {payload.get('count', 0)}")
    for secret in payload.get("secrets", []):
        row = [f"id={secret.get('id')}", f"name={secret.get('name')}"]
        if secret.get("service_name"):
            row.append(f"service={secret.get('service_name')}")
        if secret.get("expire_date"):
            row.append(f"expire={secret.get('expire_date')}")
        if args.show_values:
            row.append(f"value={secret.get('value')}")
        print(" - " + " | ".join(row))
    return 0


def cmd_add_secret(args: argparse.Namespace) -> int:
    base_url, session = _authed_session(args)
    payload = {
        "environment": args.environment,
        "folder": args.folder,
        "name": args.name,
        "value": args.value,
        "service_name": args.service_name,
        "expire_date": args.expire_date or "",
    }
    response = session.post(f"{base_url}/secrets/cli/secrets/add/", json=payload, timeout=20)
    if response.status_code not in {200, 201}:
        raise CliError(f"Create failed: {_extract_error(response)}")

    created = response.json().get("secret", {})
    print(f"Created secret id={created.get('id')} name={created.get('name')}")
    return 0


def cmd_delete_secret(args: argparse.Namespace) -> int:
    base_url, session = _authed_session(args)
    payload: dict[str, Any] = {
        "environment": args.environment,
        "folder": args.folder,
    }
    if args.id is not None:
        payload["id"] = args.id
    if args.name is not None:
        payload["name"] = args.name

    response = session.post(f"{base_url}/secrets/cli/secrets/delete/", json=payload, timeout=20)
    if response.status_code != 200:
        raise CliError(f"Delete failed: {_extract_error(response)}")

    deleted = response.json().get("deleted", {})
    print(f"Deleted secret id={deleted.get('id')} name={deleted.get('name')}")
    return 0


def cmd_apply_policy(args: argparse.Namespace) -> int:
    base_url, session = _authed_session(args)
    policy_path = Path(args.file).expanduser()
    if not policy_path.exists() or not policy_path.is_file():
        raise CliError(f"Policy file not found: {policy_path}")

    try:
        policy_document = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CliError(f"Unable to read policy file: {exc}") from exc

    payload = {
        "policy_document": policy_document,
        "document_format": args.format,
    }
    response = session.post(f"{base_url}/secrets/cli/policies/apply/", json=payload, timeout=20)
    if response.status_code != 200:
        raise CliError(f"Policy apply failed: {_extract_error(response)}")

    result = response.json()
    print(
        f"Policy applied from {policy_path}. "
        f"Updated {result.get('updated_rules', 0)} rule(s), "
        f"skipped {result.get('skipped_rules', 0)}."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="civault", description="civault CLI client")
    parser.add_argument("--url", help="Override configured vault URL for this command")
    subparsers = parser.add_subparsers(dest="command", required=True)

    configure = subparsers.add_parser("configure", help="Configure the civault server URL")
    configure.add_argument("--url", required=True, help="Base URL, e.g. http://127.0.0.1:8000")
    configure.set_defaults(func=cmd_configure)

    show_config = subparsers.add_parser("show-config", help="Print current civault configuration")
    show_config.set_defaults(func=cmd_show_config)

    login = subparsers.add_parser("login", help="Authenticate against the configured civault server")
    login.add_argument("--username", help="Vault username")
    login.add_argument("--password", help="Vault password")
    login.add_argument("--root-token", help="Optional root token authentication")
    login.set_defaults(func=cmd_login)

    logout = subparsers.add_parser("logout", help="Clear local civault session")
    logout.set_defaults(func=cmd_logout)

    status = subparsers.add_parser("status", help="Check session/authentication status")
    status.set_defaults(func=cmd_status)

    list_cmd = subparsers.add_parser("list-secrets", help="List secrets in an environment/folder")
    list_cmd.add_argument("--environment", required=True)
    list_cmd.add_argument("--folder", required=True)
    list_cmd.add_argument("--show-values", action="store_true")
    list_cmd.set_defaults(func=cmd_list_secrets)

    add_cmd = subparsers.add_parser("add-secret", help="Create a secret")
    add_cmd.add_argument("--environment", required=True)
    add_cmd.add_argument("--folder", required=True)
    add_cmd.add_argument("--name", required=True)
    add_cmd.add_argument("--value", required=True)
    add_cmd.add_argument("--service-name", default="")
    add_cmd.add_argument("--expire-date", help="YYYY-MM-DD")
    add_cmd.set_defaults(func=cmd_add_secret)

    del_cmd = subparsers.add_parser("delete-secret", help="Delete a secret by id or name")
    del_cmd.add_argument("--environment", required=True)
    del_cmd.add_argument("--folder", required=True)
    group = del_cmd.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", type=int)
    group.add_argument("--name")
    del_cmd.set_defaults(func=cmd_delete_secret)

    apply_policy = subparsers.add_parser("apply-policy", help="Apply an access policy document")
    apply_policy.add_argument("--file", required=True, help="Path to policy document file")
    apply_policy.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Policy document format (default: json)",
    )
    apply_policy.set_defaults(func=cmd_apply_policy)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except requests.RequestException as exc:
        print(f"ERROR: Request failed: {exc}")
        return 1
    except CliError as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

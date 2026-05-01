# 🔐 CI-Vault

CI-Vault is a Django-based web application designed to manage audit logs, IP tracking, location detection, scheduling tasks, and cryptographic security operations.

---

## 🚀 Features

- User Authentication
- Audit Logging
- IP Address Tracking
- Location Detection from IP
- Background Scheduling (APScheduler)
- Cryptographic Security Handling
- Secure HTTP Requests using Requests Library

---

## 🛠 Tech Stack

- Python 3.10+
- Django
- SQLite (Default Database)
- APScheduler
- Requests
- Cryptography
- tzlocal
- sqlparse
- cffi

---

## 📂 Project Structure

CI-Vault/
│
├── vault/              # Main Django app
├── manage.py
├── requirements.txt
├── README.md
└── venv/

---

## ⚙️ Installation & Setup Guide

### 1️⃣ Clone the Repository

```bash
git clone <your-repository-url>
cd CI-Vault
```

---

### 2️⃣ Create Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

**Windows**
```bash
venv\Scripts\activate
```

**Mac/Linux**
```bash
source venv/bin/activate
```

---

### 3️⃣ Upgrade pip

```bash
python -m pip install --upgrade pip setuptools wheel
```

---

### 4️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 5️⃣ Run Migrations

```bash
python manage.py migrate
```

---

### 6️⃣ Run Development Server

```bash
python manage.py runserver localhost:8000 
```

Server will run at:

http://127.0.0.1:8000/ or localhost:8000 

---

## 📦 Requirements File

Make sure your `requirements.txt` contains:

```
Django>=4.2
requests>=2.31.0
APScheduler>=3.10.4
tzlocal>=5.2
cryptography>=42.0.0
cffi>=1.16.0
sqlparse>=0.4.4
pytz>=2024.1
```

---

## 🔒 Security Notes

- Never commit `venv/` to Git
- Do not expose SECRET_KEY publicly
- Use environment variables in production
- Set `DEBUG = False` in production
- Use PostgreSQL for production deployment

---

## 📌 Best Practices

- Always use virtual environments
- Install dependencies using requirements.txt
- Keep dependencies updated
- Use `.gitignore` for sensitive files

Recommended `.gitignore`:

```
venv/
__pycache__/
*.pyc
db.sqlite3
.env
```

---

## 🚀 Future Enhancements

- JWT Authentication
- Role-Based Access Control
- REST API Support

---

## 👨‍💻 Author

Shaik Mahammad Gouse

---


---

## 🤖 Vault CLI Agent (Command Prompt)

You can now manage secrets from the terminal without using the web UI.

### CLI file

- `cli/vault_agent.py`
- `cli/civault.py` (remote CLI for server URL based access)

### What it supports

- `login`: authenticate once and save a local CLI session
- `list-secrets`: list all secrets in an environment/folder
- `add-secret`: add a new secret in an environment/folder
- `delete-secret`: delete a secret by id or name
- `logout`: clear local CLI session
- `policy-list`: list policy engine access policies
- `policy-save`: create/update policy engine access policy for a user/scope
- `policy-apply`: apply policy rules from YAML/JSON document
- `policy-delete`: delete policy engine access policy by id or by user/scope

### Policy engine (what this policy means)

The policy commands enforce **who can do what, and where** when operating secrets from the CLI.

- **Principal**: the user account the policy is assigned to.
- **Scope**: the target area the rule applies to (for example, environment and/or folder).
- **Allowed actions**: operations a user can perform in that scope (for example, list, add, or delete).

In practice, this gives you centralized access control without changing application code every time permissions change.

Typical flow:

1. Use `policy-save` to create or update a user policy for a scope.
2. Use `policy-list` to verify active policies.
3. Use `policy-apply` to load multiple rules from YAML/JSON in one step.
4. Use `policy-delete` to remove outdated or incorrect permissions.

This policy model helps teams apply least-privilege access, reduce accidental secret exposure, and keep permission changes auditable over time.

Explicit `policy-apply` JSON example:

```json
{
  "rules": [
    {
      "user": "alice",
      "new_username": "true",
      "password": "alice-pass",
      "environment": "*",
      "folder": "*",
      "secret": "*",
      "permissions": { "read": true, "write": false, "delete": false }
    }
  ]
}
```

### Install + run (Windows CMD / PowerShell / macOS / Linux)

```bash
# 1) Clone and enter project
git clone <your-repository-url>
cd ci-secrets-management

# 2) Create and activate virtual env
python -m venv .venv

# Windows CMD
.venv\Scripts\activate

# PowerShell
# .venv\Scripts\Activate.ps1

# macOS/Linux
# source .venv/bin/activate

# 3) Install dependencies
pip install -r requirements.txt

# 4) Apply migrations
python manage.py migrate

# 5) Show CLI help
python cli/vault_agent.py --help
```

### Authentication model for CLI

Use one of these as `--root-token`:

1. `VAULT_KEK` value from Django settings (operator token)
2. Base64 root key token (if you already have the vault root key)

You can authenticate once and save session:

```bash
python cli/vault_agent.py login --root-token "<YOUR_ROOT_TOKEN_OR_KEK>"
```

After login, the token is stored locally in:

- `~/.vault_cli_session.json`

---

## 🧰 civault CLI (URL-first workflow)

If users want to connect to a running vault server through CLI, use **civault**.

### Install CLI package (required)

```bash
# from repository root
python -m pip install .

# verify binary
civault --help
```

All Vault operations for remote access should be executed via the installed `civault` command.

### Key flow

1. Configure URL once.
2. Authenticate.
3. Run secret operations.

### Commands

```bash
# Configure vault URL (required first step)
civault configure --url http://127.0.0.1:8000

# Login (username/password)
civault login --username admin --password <PASSWORD>

# or Login with root token
civault login --root-token <ROOT_TOKEN>

# Check status
civault status

# List secrets
civault list-secrets --environment prod --folder payments

# Add secret
civault add-secret --environment prod --folder payments --name API_KEY --value supersecret

# Delete secret by name or id
civault delete-secret --environment prod --folder payments --name API_KEY
civault delete-secret --environment prod --folder payments --id 1
```

### civault local files

- Config: `~/.civault/config.json`
- Session cookies: `~/.civault/session.json`

You can also avoid local session and pass token every command:

```bash
python cli/vault_agent.py list-secrets --root-token "<TOKEN>" --environment prod --folder payments --show-values
```

Or set environment variable:

```bash
# Linux/macOS
export VAULT_ROOT_TOKEN="<TOKEN>"

# Windows CMD
set VAULT_ROOT_TOKEN=<TOKEN>

# PowerShell
# $env:VAULT_ROOT_TOKEN="<TOKEN>"
```

### CLI usage examples

```bash
# Login once
python cli/vault_agent.py login --root-token "<TOKEN>"

# List secrets in env/folder
python cli/vault_agent.py list-secrets --environment production --folder backend --show-values

# Add secret
python cli/vault_agent.py add-secret \
  --environment production \
  --folder backend \
  --name STRIPE_API_KEY \
  --value "sk_live_xxx" \
  --service-name stripe \
  --expire-date 2026-12-31

# Delete secret by name
python cli/vault_agent.py delete-secret --environment production --folder backend --name STRIPE_API_KEY

# Delete secret by id
python cli/vault_agent.py delete-secret --environment production --folder backend --id 12

# Logout / clear local CLI session
python cli/vault_agent.py logout

# Policy Engine (CLI): list all policies
python cli/vault_agent.py policy-list

# Policy Engine (CLI): grant read+write for user on environment scope
python cli/vault_agent.py policy-save \
  --user alice \
  --environment production \
  --read --write

# Policy Engine (CLI): grant read for user on secret scope
python cli/vault_agent.py policy-save \
  --user alice \
  --environment production \
  --folder backend \
  --secret STRIPE_API_KEY \
  --read

# Policy Engine (CLI): delete by policy id
python cli/vault_agent.py policy-delete --policy-id 12

# Policy Engine (CLI): apply rules from YAML/JSON file
python cli/vault_agent.py policy-apply --file policy.yaml --format yaml

# Policy Engine (CLI): bulk delete policies from JSON file
python cli/vault_agent.py policy-delete --file delete_policies.json --format json
```

### Policy Engine CLI (easy mode)

Use these two document templates and apply them directly:

**`policy.yaml`**

```yaml
rules:
  - user: alice
    environment: production
    folder: backend
    secret: STRIPE_API_KEY
    permissions:
      read: true
      write: false
      delete: false
```

Apply:

```bash
python cli/vault_agent.py policy-apply --file policy.yaml --format yaml
```

### JSON example: create user and apply policy in one step

You can also apply a JSON policy document that creates a user when `new_username` is set to `"true"` and then applies the rule so it appears in **Recent Access Rules** in UI.

**`policy.json`**

```json
{
  "rules": [
    {
      "user": "alice",
      "new_username": "true",
      "password": "alice-pass",
      "environment": "prod",
      "folder": "payments",
      "secret": "STRIPE_API_KEY",
      "permissions": {
        "read": true,
        "write": false,
        "delete": false
      }
    }
  ]
}
```

Apply it with:

```bash
python cli/vault_agent.py policy-apply --file policy.json --format json
```

Scope shortcuts supported in policy rules:

- Use `*` for all values at that level (`environment`, `folder`, `secret`).
- Use comma-separated names for multiple values, for example:
  - `"folder": "payments,billing"`
  - `"secret": "STRIPE_API_KEY,STRIPE_WEBHOOK_SECRET"`

**`delete_policies.json`**

```json
{
  "policies": [
    { "policy_id": 12 },
    { "user": "alice", "environment": "production", "folder": "backend", "secret": "STRIPE_API_KEY" }
  ]
}
```

Delete:

```bash
python cli/vault_agent.py policy-delete --file delete_policies.json --format json
```

### Notes

- `list-secrets --show-values` decrypts and prints plaintext values.
- `add-secret` stores values encrypted using the same root-key approach as the web app.
- The CLI expects environment/folder names to already exist.

---

## 🔧 JWT Machine Login Endpoint (Policy Engine)

Machine/workload identities can authenticate with JWT using:

- `POST /secrets/policy-engine/machine/jwt/login/`

Request body:

```json
{
  "jwt": "<signed workload JWT>",
  "identity_name": "optional-jwt-identity-name"
}
```

Response includes:

- `machine_token` (generated vault machine session token)
- `expires_in` / `expires_at`
- resolved `machine_policy`
- effective access scope (`read/write/delete`)

---

## 🔧 AppRole Machine Login Endpoint (Policy Engine)

Machine/workload identities can authenticate with AppRole credentials using:

- `POST /secrets/policy-engine/machine/approle/login/`

Request body:

```json
{
  "role_id": "<approle role id>",
  "secret_id": "<approle secret id>"
}
```

Response includes:

- `machine_token` (generated vault machine session token)
- `expires_in` / `expires_at` (uses AppRole token TTL)
- resolved `machine_policy`
- effective access scope (`read/write/delete`)

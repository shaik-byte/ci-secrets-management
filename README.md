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

### What it supports

- `login`: authenticate once and save a local CLI session
- `list-secrets`: list all secrets in an environment/folder
- `add-secret`: add a new secret in an environment/folder
- `delete-secret`: delete a secret by id or name
- `logout`: clear local CLI session

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

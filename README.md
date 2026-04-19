# civault-cli

Standalone Python CLI package for interacting with a CI Vault server.

This branch (`cli-package`) intentionally contains only the installable CLI package code. It excludes all Django/Vault backend implementation.

## Features

- Configure and persist a Vault server URL
- Authenticate using username/password or root token
- Persist CLI session cookies locally
- Check CLI authentication status
- List secrets
- Get a single secret by id or name
- Add secrets
- Delete secrets
- Apply access policies from JSON/YAML documents

## Installation

### From local source

```bash
python -m pip install .
```

### Editable install for development

```bash
python -m pip install -e .
```

## Usage

After installation, use the `civault` command:

```bash
civault --help
```

### 1) Configure server URL

```bash
civault configure --url http://127.0.0.1:8000
```

### 2) Login

Using username/password:

```bash
civault login --username admin --password secret
```

Using a root token:

```bash
civault login --root-token <TOKEN>
```

### 3) Validate session

```bash
civault status
```

### 4) Secret operations

```bash
civault list-secrets --environment prod --folder payments
civault get-secret --environment prod --folder payments --name API_KEY
civault add-secret --environment prod --folder payments --name API_KEY --value supersecret
civault delete-secret --environment prod --folder payments --name API_KEY
```

### 5) Apply policy document

Create a policy file (JSON):

```json
{
  "rules": [
    {
      "user": "alice",
      "environment": "prod",
      "folder": "payments",
      "permissions": {
        "read": true,
        "write": false,
        "delete": false
      }
    },
    {
      "user": "alice",
      "environment": "prod",
      "folder": "payments",
      "secret": "API_KEY",
      "permissions": {
        "read": true,
        "write": false,
        "delete": false
      }
    }
  ]
}
```

Apply it:

```bash
civault policy-apply --file ./policy.json
```

Or YAML:

```bash
civault policy-apply --file ./policy.yaml --format yaml
```

> Note: policy rules are matched by exact names from the server (especially `user` as the exact username).  
> If no records match, the server may process `0` rules.
> The CLI auto-detects secret-level rules (`secret`, `secret_name`, `secretId`, etc.) and uses the secret policy endpoint automatically.
> For older servers that do not expose the secret endpoint yet, the CLI falls back to the standard policy endpoint when it receives HTTP 404.

## Local config/session files

The CLI stores local state in:

- `~/.civault/config.json`
- `~/.civault/session.json`

## Python support

- Python 3.10+

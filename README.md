# civault-cli

Standalone Python CLI package for interacting with a CI Vault server.

This branch (`cli-package`) intentionally contains only the installable CLI package code. It excludes all Django/Vault backend implementation.

## Features

- Configure and persist a Vault server URL
- Authenticate using username/password or root token
- Persist CLI session cookies locally
- Check CLI authentication status
- List secrets
- Add secrets
- Delete secrets

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
civault add-secret --environment prod --folder payments --name API_KEY --value supersecret
civault delete-secret --environment prod --folder payments --name API_KEY
```

## Local config/session files

The CLI stores local state in:

- `~/.civault/config.json`
- `~/.civault/session.json`

## Python support

- Python 3.10+

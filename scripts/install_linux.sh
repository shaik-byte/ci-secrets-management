#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install .

echo "Installed vaultcli. Run: vaultcli --help"

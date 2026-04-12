$ErrorActionPreference = "Stop"

python -m pip install --upgrade pip
python -m pip install .

Write-Host "Installed vaultcli. Run: vaultcli --help"

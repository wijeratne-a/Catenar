# Ensure policy.json exists for proxy. Creates from policy.json.example if missing.
# Usage: .\scripts\ensure-policy.ps1
# Run before first docker compose up.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

if (-not (Test-Path "policy.json")) {
    Copy-Item "policy.json.example" "policy.json"
    Write-Host "Created policy.json from policy.json.example"
}

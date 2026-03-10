# Catenar demo script for Windows: sets env vars and starts infrastructure.
# Usage: .\scripts\demo.ps1 [-RunAgent]
#   -RunAgent: after infra is up, run python sdks/python/agent.py --demo

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

# Policy.json for new clones
if (-not (Test-Path "policy.json")) {
    Copy-Item "policy.json.example" "policy.json"
    Write-Host "Created policy.json from policy.json.example"
}

# Env for proxy and CA
$env:HTTP_PROXY = if ($env:HTTP_PROXY) { $env:HTTP_PROXY } else { "http://127.0.0.1:8080" }
$env:HTTPS_PROXY = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } else { "http://127.0.0.1:8080" }
$env:NO_PROXY = if ($env:NO_PROXY) { $env:NO_PROXY } else { "127.0.0.1,localhost" }
$env:CATENAR_DEMO = "1"

$CaPath = Join-Path $RepoRoot "deploy\certs\ca.crt"
if (Test-Path $CaPath) {
    $env:REQUESTS_CA_BUNDLE = $CaPath
    $env:SSL_CERT_FILE = $CaPath
}

# Start infra
docker compose up -d --wait verifier proxy web prometheus grafana

Write-Host ""
Write-Host "Dashboard: http://localhost:3001 | Grafana: http://localhost:3002"
Write-Host "Demo: cd sdks\python; python agent.py --demo"
Write-Host "Set CATENAR_DEMO=1 for auto proxy/CA config"

if ($args -contains "-RunAgent") {
    Write-Host ""
    Write-Host "Running agent demo..."
    Set-Location (Join-Path $RepoRoot "sdks\python")
    python agent.py --demo
}

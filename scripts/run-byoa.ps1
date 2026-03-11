# Run Bring Your Own Agent from any directory.
# Prerequisites: docker compose up -d verifier proxy
# Usage: .\scripts\run-byoa.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$env:CATENAR_DEMO = "1"
$env:HTTP_PROXY = if ($env:HTTP_PROXY) { $env:HTTP_PROXY } else { "http://127.0.0.1:8080" }
$env:HTTPS_PROXY = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } else { "http://127.0.0.1:8080" }
$env:NO_PROXY = if ($env:NO_PROXY) { $env:NO_PROXY } else { "127.0.0.1,localhost" }

$CaPath = Join-Path $RepoRoot "deploy\certs\ca.crt"
if (Test-Path $CaPath) {
    $env:REQUESTS_CA_BUNDLE = $CaPath
    $env:SSL_CERT_FILE = $CaPath
}

python examples/bring_your_own_agent.py

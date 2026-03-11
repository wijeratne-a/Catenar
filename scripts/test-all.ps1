# Run all unit/integration tests. Exit 1 on first failure.
# Usage: .\scripts\test-all.ps1 [-Swarm]
#   -Swarm: after unit tests, run swarm demo (requires verifier+proxy up)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$RunSwarm = $false
foreach ($arg in $args) {
    if ($arg -eq "-Swarm") {
        $RunSwarm = $true
        break
    }
}

function Write-Step { param($Name) Write-Host "=== $Name ===" -ForegroundColor Cyan }
function Write-Ok { param($Name) Write-Host "$Name`: OK" -ForegroundColor Green }

Write-Step "Verifier"
Set-Location "$RepoRoot\core\verifier"
cargo test --release
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Ok "Verifier"
Write-Host ""

Write-Step "Proxy"
Set-Location "$RepoRoot\core\proxy"
cargo test
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Ok "Proxy"
Write-Host ""

Write-Step "catenar-verify"
Set-Location "$RepoRoot\tools\catenar-verify"
cargo test
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Ok "catenar-verify"
Write-Host ""

Write-Step "Python SDK"
Set-Location "$RepoRoot\sdks\python"
python -m pytest
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Ok "Python SDK"
Write-Host ""

Write-Step "Dashboard"
Set-Location "$RepoRoot\dashboard"
npm test
if ($LASTEXITCODE -ne 0) { exit 1 }
npm run lint
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Ok "Dashboard"
Write-Host ""

if ($RunSwarm) {
    Write-Step "Swarm demo (E2E)"
    if (-not (Test-Path policy.json)) { Copy-Item policy.json.example policy.json }
    docker compose up -d --wait verifier proxy
    python examples/swarm_demo.py
    if ($LASTEXITCODE -ne 0) { Write-Host "Swarm demo failed"; exit 1 }
    Write-Ok "Swarm"
}

Write-Host ""
Write-Host "All tests passed." -ForegroundColor Green

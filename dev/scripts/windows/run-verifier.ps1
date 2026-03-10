# Wrapper to run the Catenar verifier from Cursor (or any) terminal on Windows.
# Tries MSVC via VsDevCmd.bat, then GNU toolchain with optional MinGW auto-detect or CATENAR_MINGW.
# Run from repo root: .\dev\scripts\windows\run-verifier.ps1
$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { (Get-Item $PSScriptRoot).FullName } else { (Get-Location).Path }
$rootDir = (Get-Item $scriptDir).Parent.Parent.Parent.FullName
$verifierDir = Join-Path $rootDir "core\verifier"

$vsBases = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
)
$vsScript = $null
$vsBatch = $null
foreach ($base in $vsBases) {
    if (Test-Path -LiteralPath $base) {
        $vsScript = Join-Path $base "Common7\Tools\Launch-VsDevShell.ps1"
        $vsBatch = Join-Path $base "Common7\Tools\VsDevCmd.bat"
        break
    }
}

$scriptExists = $vsScript -and (Test-Path -LiteralPath $vsScript)

# Prefer cmd + VsDevCmd.bat so cargo runs in a process with MSVC on PATH (Launch-VsDevShell.ps1
# does not reliably set link.exe in the current process when invoked with &).
if ($vsBatch -and (Test-Path -LiteralPath $vsBatch)) {
    $cmd = "call `"$vsBatch`" -arch=amd64 && cd /d `"$verifierDir`" && cargo run"
    & cmd /c $cmd
    $msvcExit = $LASTEXITCODE
    if ($msvcExit -eq 0) { exit 0 }
    # Fallback: try GNU toolchain (no VS C++ workload needed if MinGW is installed)
    $rustup = Get-Command rustup -ErrorAction SilentlyContinue
    if ($rustup) {
        Write-Host "MSVC build failed. Trying GNU toolchain..." -ForegroundColor Cyan
        $errPref = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        try { & rustup toolchain install stable-x86_64-pc-windows-gnu 2>&1 | Out-Null } catch { }
        $ErrorActionPreference = $errPref
        # Prepend MinGW/binutils path so dlltool.exe and gcc are found.
        $mingwDir = $env:CATENAR_MINGW
        if (-not $mingwDir) {
            $mingwCandidates = @(
                "C:\msys64\ucrt64\bin", "C:\msys64\mingw64\bin", "C:\msys64\mingw32\bin",
                "C:\msys32\mingw64\bin", "C:\MinGW\bin", "C:\mingw64\bin"
            )
            foreach ($dir in $mingwCandidates) {
                if (Test-Path -LiteralPath (Join-Path $dir "dlltool.exe")) {
                    $mingwDir = $dir
                    break
                }
            }
        }
        if ($mingwDir -and (Test-Path -LiteralPath (Join-Path $mingwDir "dlltool.exe"))) {
            $env:PATH = $mingwDir + ";" + $env:PATH
        }
        Push-Location $verifierDir
        try {
            & rustup run stable-x86_64-pc-windows-gnu cargo run
            exit $LASTEXITCODE
        } finally {
            Pop-Location
        }
    }
    Write-Host ""
    Write-Host "If you see 'link.exe not found' or 'The system cannot find the file specified':" -ForegroundColor Yellow
    Write-Host "  1. Open Visual Studio Installer, modify Build Tools, and ensure 'Desktop development with C++' is installed." -ForegroundColor Yellow
    Write-Host "  2. Or use GNU: install MinGW-w64 with binutils (e.g. MSYS2: pacman -S mingw-w64-ucrt-x86_64-toolchain). If not in C:\msys64, set CATENAR_MINGW to the bin folder, then run this script again." -ForegroundColor Yellow
    exit $msvcExit
}
if ($scriptExists) {
    try {
        & $vsScript -Arch amd64
        Push-Location $verifierDir
        try { cargo run } finally { Pop-Location }
    } catch {
        throw
    }
} else {
    Write-Host "No Launch-VsDevShell.ps1 or VsDevCmd.bat found. Install Build Tools with C++ workload."
    exit 1
}

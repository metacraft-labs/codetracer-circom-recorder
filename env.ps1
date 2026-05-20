# codetracer-circom-recorder Windows dev environment (PowerShell)
# Usage: . .\env.ps1
#
# The recorder builds and tests with a plain `cargo build` / `cargo test`.
# Its Windows requirements are:
#
#   1. The shared CodeTracer toolchain (Rust, Nim + nimble, just, Cap'n Proto,
#      MSVC).  These are provisioned by the main `codetracer` repo's env.ps1,
#      which this script dot-sources.  Nim is needed because the
#      `codetracer_trace_writer_nim` crate's build script compiles a Nim
#      static library.
#
#   2. An explicit MSVC linker for the `x86_64-pc-windows-msvc` target -- see
#      the comment block below `WINDOWS_DIY_CL_EXE`.
#
#   3. The Circom compiler.  The recorder shells out to `circom` to compile a
#      `.circom` source to a witness; the Nix `circom-recorder` dev shell
#      supplies it.  Two versions are needed:
#        * circom 2.1.5 -- the version the Nix dev shell pins; the bulk of the
#          test corpus is authored against it.  Provisioned onto PATH so the
#          recorder's default `circom` lookup resolves to it.
#        * circom 2.2.3 -- required by the `bus_type` fixtures, whose
#          `pragma circom 2.2.0;` is rejected by 2.1.5.  The test harness
#          honours `CIRCOM_2_2_BIN` for this binary.
#      Both are the official prebuilt `circom-windows-amd64.exe` releases from
#      `iden3/circom` (Circom is itself a Rust project; the published Windows
#      binary is the canonical artefact).

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- 1. Shared CodeTracer toolchain -----------------------------------------
$env:WINDOWS_DIY_SKIP_FPC = "1"
$env:WINDOWS_DIY_SKIP_LLVM = "1"
$env:WINDOWS_DIY_SKIP_NARGO = "1"
$env:WINDOWS_DIY_SKIP_DOTNET = "1"

$codetracerEnv = Join-Path (Split-Path -Parent $scriptDir) "codetracer\env.ps1"
if (-not (Test-Path $codetracerEnv)) {
    throw "Could not find the shared CodeTracer env.ps1 at $codetracerEnv -- the ``codetracer`` repo must be checked out as a sibling of this repo."
}
. $codetracerEnv

# --- 2. Explicit MSVC linker (immune to Git Bash PATH reordering) -----------
# The `just test` recipe runs `verify-cli-convention-no-silent-skip.sh` via
# bash, which invokes `cargo build`.  A bash login shell re-orders PATH so
# Git Bash's coreutils `link.exe` precedes the MSVC toolchain; cargo would
# then link with the wrong `link.exe`.  Pinning the linker by absolute path
# bypasses PATH resolution.
if ($env:WINDOWS_DIY_CL_EXE -and (Test-Path $env:WINDOWS_DIY_CL_EXE)) {
    $msvcBin = Split-Path -Parent $env:WINDOWS_DIY_CL_EXE
    $msvcLink = Join-Path $msvcBin "link.exe"
    if (Test-Path $msvcLink) {
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $msvcLink
    }
    if ($env:Path -notlike "$msvcBin;*") {
        $env:Path = "$msvcBin;$($env:Path)"
    }
}

# --- 3. Circom compiler (2.1.5 default + 2.2.3 for bus fixtures) -------------
$devDepsRoot = if ($env:WINDOWS_DIY_INSTALL_ROOT) { $env:WINDOWS_DIY_INSTALL_ROOT }
               elseif (Test-Path "D:\") { "D:\metacraft-dev-deps" }
               else { Join-Path $env:LOCALAPPDATA "codetracer\windows-diy" }

function Install-Circom {
    param([string]$Version)
    $dir = Join-Path $devDepsRoot "circom\$Version"
    $exe = Join-Path $dir "circom.exe"
    if (Test-Path $exe) {
        Write-Host "circom $Version already installed"
        return $exe
    }
    Write-Host "Installing circom $Version..."
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $url = "https://github.com/iden3/circom/releases/download/v$Version/circom-windows-amd64.exe"
    Invoke-WebRequest -Uri $url -OutFile $exe
    $reported = (& $exe --version 2>&1)
    if ($reported -notmatch [regex]::Escape($Version)) {
        throw "circom $Version self-check failed: '$reported'"
    }
    Write-Host "Installed circom $Version to $dir"
    return $exe
}

$circom215 = Install-Circom -Version "2.1.5"
$circom223 = Install-Circom -Version "2.2.3"

# circom 2.1.5 is the recorder's default `circom`: put its dir on PATH.
$circom215Dir = Split-Path -Parent $circom215
if ($env:Path -notlike "*$circom215Dir*") {
    $env:Path = "$circom215Dir;$($env:Path)"
}
# The `bus_type` tests route the recorder through circom 2.2.3 via this var.
$env:CIRCOM_2_2_BIN = $circom223

Write-Host "circom (default): $((& circom --version) 2>&1)"
Write-Host "CIRCOM_2_2_BIN=$env:CIRCOM_2_2_BIN"
Write-Host "codetracer-circom-recorder dev environment ready."

<#
.SYNOPSIS  Build the Vigil MSI. Requires: Rust, pnpm, and the WiX CLI (dotnet tool install --global wix).
.EXAMPLE   .\installer\build.ps1 -Version 1.0.0 [-SignCert <thumbprint>]
#>
param(
    [string]$Version = '1.0.0',
    [string]$SignCert = '',
    # build: compile and stage dist/bin only (CI signs the binaries next); package: wrap dist/bin in the MSI.
    [ValidateSet('all', 'build', 'package')][string]$Stage = 'all'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$bin = Join-Path $root 'dist\bin'
if ($Stage -ne 'package') {
    cargo build --release -p vigil-svc -p vigilctl
    if ($LASTEXITCODE) { throw 'service build failed' }
    pnpm -C apps/ui install --frozen-lockfile
    pnpm -C apps/ui build
    cargo build --release --manifest-path apps/ui/src-tauri/Cargo.toml
    if ($LASTEXITCODE) { throw 'ui build failed' }
    New-Item -ItemType Directory -Force $bin | Out-Null
    Copy-Item target\release\vigil-svc.exe, target\release\vigilctl.exe $bin -Force
    Copy-Item apps\ui\src-tauri\target\release\vigil-ui.exe $bin -Force
    if ($Stage -eq 'build') { Write-Host "Staged $bin"; return }
}

if ($SignCert) {
    Get-ChildItem $bin -Filter *.exe | ForEach-Object {
        signtool sign /sha1 $SignCert /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $_.FullName
        if ($LASTEXITCODE) { throw "signing $($_.Name) failed" }
    }
}

wix extension add -g WixToolset.Util.wixext | Out-Null
$msi = Join-Path $root "dist\Vigil-$Version.msi"
wix build installer\Vigil.wxs -ext WixToolset.Util.wixext -d Version=$Version -d BinDir=$bin -arch x64 -o $msi
if ($LASTEXITCODE) { throw 'wix build failed' }
if ($SignCert) { signtool sign /sha1 $SignCert /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $msi }
Get-FileHash $msi -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $(Split-Path -Leaf $msi)" } | Set-Content "$msi.sha256"
Write-Host "Built $msi"

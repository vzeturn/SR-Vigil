<#
.SYNOPSIS  Build the Vigil MSI. Requires: Rust, pnpm, and the WiX CLI (dotnet tool install --global wix).
.EXAMPLE   .\installer\build.ps1 -Version 1.0.0 [-Arch arm64] [-SignCert <thumbprint>]
.NOTES     -Arch arm64 cross-compiles on an x64 host; it needs the MSVC ARM64 build tools and clang (ring).
#>
param(
    [string]$Version = '1.0.0',
    [string]$SignCert = '',
    [ValidateSet('x64', 'arm64')][string]$Arch = 'x64',
    # build: compile and stage dist/bin only (CI signs the binaries next); package: wrap dist/bin in the MSI.
    [ValidateSet('all', 'build', 'package')][string]$Stage = 'all'
)
$ErrorActionPreference = 'Stop'
$Version = $Version.TrimStart('v')   # tags are vX.Y.Z; MSI versions are numeric
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$triple = @{ x64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$Arch]
$bin = Join-Path $root "dist\bin\$Arch"
if ($Stage -ne 'package') {
    rustup target add $triple
    if ($LASTEXITCODE) { throw "rust target $triple unavailable" }
    cargo build --release --target $triple -p vigil-svc -p vigilctl
    if ($LASTEXITCODE) { throw 'service build failed' }
    pnpm -C apps/ui install --frozen-lockfile
    pnpm -C apps/ui build
    cargo build --release --target $triple --manifest-path apps/ui/src-tauri/Cargo.toml
    if ($LASTEXITCODE) { throw 'ui build failed' }
    New-Item -ItemType Directory -Force $bin | Out-Null
    Copy-Item "target\$triple\release\vigil-svc.exe", "target\$triple\release\vigilctl.exe" $bin -Force
    Copy-Item "apps\ui\src-tauri\target\$triple\release\vigil-ui.exe" $bin -Force
    if ($Stage -eq 'build') { Write-Host "Staged $bin"; return }
}

if ($SignCert) {
    Get-ChildItem $bin -Filter *.exe | ForEach-Object {
        signtool sign /sha1 $SignCert /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $_.FullName
        if ($LASTEXITCODE) { throw "signing $($_.Name) failed" }
    }
}

# The extension must match the WiX CLI major version or `wix build` cannot load it.
$wixVersion = (wix --version) -replace '\+.*$', ''
wix extension add -g "WixToolset.Util.wixext/$wixVersion" | Out-Null
if ($LASTEXITCODE) { throw "WiX Util extension $wixVersion unavailable" }
# x64 keeps the plain name so existing download links stay valid.
$suffix = if ($Arch -eq 'x64') { '' } else { "-$Arch" }
$msi = Join-Path $root "dist\Vigil-$Version$suffix.msi"
wix build installer\Vigil.wxs -ext "WixToolset.Util.wixext/$wixVersion" -d Version=$Version -d BinDir=$bin -arch $Arch -o $msi
if ($LASTEXITCODE) { throw 'wix build failed' }
if ($SignCert) { signtool sign /sha1 $SignCert /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $msi }
Get-FileHash $msi -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $(Split-Path -Leaf $msi)" } | Set-Content "$msi.sha256"
Write-Host "Built $msi"

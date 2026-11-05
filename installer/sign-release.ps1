# Signs a built installer for the tray's updater. Run after building the installer (src/README.md):
#   .\installer\sign-release.ps1 -SecretKey D:\keys\foxhole.key [-NotesFile notes.txt]
#
# Writes foxhole-update.json and foxhole-update.json.minisig next to the installer. minisign asks
# for the key's password. Attach all three files to the GitHub release.

param(
    [Parameter(Mandatory)][string]$SecretKey,
    # Plain text shown in the update prompt. Signed, so it can't be edited on GitHub afterwards.
    [string]$NotesFile,
    [string]$Minisign = 'minisign'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$publicKey = Join-Path $root 'resources\update-signing.pub'

$secretKeyPath = (Resolve-Path $SecretKey).Path
if ($secretKeyPath.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) {
    throw "The secret key is inside the repository ($secretKeyPath). Move it somewhere it can't be committed."
}

$cargoVersion = Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "(.+)"$' | Select-Object -First 1
if (-not $cargoVersion) { throw 'No version found in Cargo.toml' }
$version = $cargoVersion.Matches[0].Groups[1].Value

$output = Join-Path $PSScriptRoot 'Output'
$installerName = "Foxhole-Setup-$version.exe"
$installer = Join-Path $output $installerName
if (-not (Test-Path $installer)) { throw "$installer not found. Build the installer first." }

$notes = ''
if ($NotesFile) { $notes = [IO.File]::ReadAllText((Resolve-Path $NotesFile).Path).Trim() }

$manifest = [ordered]@{
    product   = 'foxhole'
    version   = $version
    installer = $installerName
    size      = (Get-Item $installer).Length
    sha256    = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    notes     = $notes
} | ConvertTo-Json

# Not Set-Content: Windows PowerShell would add a byte order mark, which isn't valid JSON.
$manifestPath = Join-Path $output 'foxhole-update.json'
[IO.File]::WriteAllText($manifestPath, $manifest, (New-Object Text.UTF8Encoding $false))

$signaturePath = "$manifestPath.minisig"
& $Minisign -S -s $secretKeyPath -m $manifestPath -x $signaturePath -t "foxhole $version"
if ($LASTEXITCODE -ne 0) { throw 'Signing failed.' }

# Catches signing with a key other than the one built into the tray, which users would reject.
& $Minisign -V -p $publicKey -m $manifestPath -x $signaturePath
if ($LASTEXITCODE -ne 0) { throw "The signature doesn't match $publicKey." }

Write-Host "`nAttach these to the v$version release:`n  $installer`n  $manifestPath`n  $signaturePath"

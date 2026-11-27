<#
.SYNOPSIS
    Export the TLS-inspection proxy's root CA(s) into backend/certs/ so the
    container trusts them (see backend/Dockerfile).

.DESCRIPTION
    iboss re-signs outbound HTTPS with its own root CA. Windows trusts it; the
    container does not, so every feed fails CERTIFICATE_VERIFY_FAILED. This
    copies matching, unexpired root certificates (public certs only, never
    anything with a private key) from the Windows trusted root stores into
    backend/certs/auto-<thumbprint>.crt as PEM. Previously exported auto-*.crt
    files that no longer match (rotated or expired roots) are removed. On a
    device without iboss it exports nothing and exits cleanly.

    backend/certs/* is gitignored: these files must never be committed.

.EXAMPLE
    .\scripts\export-proxy-ca.ps1
    docker compose up --build -d

.EXAMPLE
    .\scripts\export-proxy-ca.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Regex matched against the certificate Subject.
    [ValidateNotNullOrEmpty()]
    [string]$SubjectPattern = 'iboss'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$certDir = Join-Path $PSScriptRoot '..\backend\certs' | Resolve-Path | Select-Object -ExpandProperty Path

$now = Get-Date
$roots = @()
if (Test-Path Cert:\) {
    $roots = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root |
        Where-Object {
            $_.Subject -match $SubjectPattern -and
            -not $_.HasPrivateKey -and
            $_.NotBefore -le $now -and
            $_.NotAfter -gt $now
        } |
        Sort-Object Thumbprint -Unique)
} else {
    Write-Host "No Windows certificate store on this platform - skipping export."
}

if (-not $roots) {
    # Not an error: devices without iboss just use the standard Mozilla roots.
    # Fall through so stale auto-*.crt from an earlier iboss install are still removed.
    Write-Host "No unexpired root CA matching '$SubjectPattern' found - nothing to export (fine if this device isn't behind iboss)."
}

$keep = @()
foreach ($cert in $roots) {
    $file = Join-Path $certDir ("auto-{0}.crt" -f $cert.Thumbprint.ToLowerInvariant())
    $keep += $file
    $b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') -replace "`r`n", "`n"
    $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    if ($PSCmdlet.ShouldProcess($file, "Write root CA '$($cert.Subject)' (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))")) {
        # LF line endings, no BOM: update-ca-certificates in the Linux image expects plain PEM.
        [IO.File]::WriteAllText($file, $pem, [Text.UTF8Encoding]::new($false))
        Write-Host "Exported $($cert.Thumbprint) -> $(Split-Path $file -Leaf) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    }
}

# Remove stale exports from earlier runs (rotated/expired roots). Only touches auto-*.crt.
Get-ChildItem -Path $certDir -Filter 'auto-*.crt' |
    Where-Object { $keep -notcontains $_.FullName } |
    ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove stale exported root CA')) {
            Remove-Item -LiteralPath $_.FullName
            Write-Host "Removed stale $($_.Name)"
        }
    }

Write-Host "Done. Rebuild to apply: docker compose up --build -d"

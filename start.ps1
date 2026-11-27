<#
.SYNOPSIS
    Export the iboss root CA (if present) and build/start the dashboard.

.DESCRIPTION
    Runs scripts/export-proxy-ca.ps1 so the container trusts iboss TLS
    inspection, then `docker compose up --build -d`. Safe on devices without
    iboss: the export step just finds nothing.

.EXAMPLE
    .\start.ps1
.EXAMPLE
    .\start.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Push-Location $PSScriptRoot
try {
    & (Join-Path $PSScriptRoot 'scripts\export-proxy-ca.ps1') -WhatIf:$WhatIfPreference

    if ($PSCmdlet.ShouldProcess('threat-feed-dashboard', 'docker compose up --build -d')) {
        docker compose up --build -d
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose failed (exit $LASTEXITCODE). Is Docker Desktop running?"
        }
        Write-Host "Dashboard: http://127.0.0.1:8070"
    }
}
finally {
    Pop-Location
}

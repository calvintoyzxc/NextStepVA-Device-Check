# ==========================================
# NextStepVA Device Compliance Checker
# Version 1.0.0
# ==========================================

$ToolVersion = "1.0.0"

$ErrorActionPreference = "Stop"


# Check Administrator

$CurrentUser = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

$IsAdmin = $CurrentUser.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)


if (-not $IsAdmin) {

    Write-Host ""
    Write-Host "ERROR: Please run PowerShell as Administrator." -ForegroundColor Red
    Write-Host ""

    Pause
    exit
}


Write-Host ""
Write-Host "========================================="
Write-Host " NextStepVA Device Compliance Checker"
Write-Host " Version $ToolVersion"
Write-Host " Running as Administrator"
Write-Host "========================================="
Write-Host ""
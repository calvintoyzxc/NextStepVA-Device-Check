#requires -Version 5.1
<#
NextStep VA - BYOD Device & Security Compliance Assessment
Purpose: Internal device security/readiness verification for BYOD onboarding.

IMPORTANT:
- This tool does NOT certify HIPAA compliance.
- It intentionally avoids collecting browser history, passwords, saved credentials,
  personal documents, personal email addresses, or browser profile names.
- Some checks require Administrator privileges for the most accurate result.
#>

$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------------------------------
# BASIC HELPERS
# ------------------------------------------------------------

function HtmlEncode([object]$Value) {
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function StatusClass([string]$Status) {
    switch ($Status) {
        "PASS"   { return "pass" }
        "FAIL"   { return "fail" }
        "REVIEW" { return "review" }
        default  { return "info" }
    }
}

function StatusHtml([string]$Status) {
    $c = StatusClass $Status
    return "<span class='status $c'>$(HtmlEncode $Status)</span>"
}

function SafeDate([object]$DateValue) {
    if ($null -eq $DateValue) { return "Not available" }
    try { return ([datetime]$DateValue).ToString("yyyy-MM-dd HH:mm:ss") }
    catch { return [string]$DateValue }
}

function Get-DownloadsPath {
    try {
        $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $guidName = "{374DE290-123F-4565-9164-39C4925E467B}"
        $raw = (Get-ItemProperty -Path $key -Name $guidName -ErrorAction Stop).$guidName
        $expanded = [Environment]::ExpandEnvironmentVariables($raw)
        if (Test-Path $expanded) { return $expanded }
    } catch {}
    $fallback = Join-Path $env:USERPROFILE "Downloads"
    if (!(Test-Path $fallback)) {
        New-Item -ItemType Directory -Path $fallback -Force | Out-Null
    }
    return $fallback
}

function Get-Sha256Text([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-BrowserVersion([string[]]$Paths) {
    foreach ($p in $Paths) {
        if (Test-Path $p) {
            try {
                $v = (Get-Item $p).VersionInfo.ProductVersion
                if ([string]::IsNullOrWhiteSpace($v)) { $v = "Installed" }
                return $v
            } catch {
                return "Installed"
            }
        }
    }
    return "Not detected"
}

# ------------------------------------------------------------
# INTRO / EMPLOYEE ID
# ------------------------------------------------------------

Clear-Host
Write-Host ""
Write-Host "============================================================"
Write-Host "                 NEXTSTEP VA"
Write-Host "       DEVICE & SECURITY COMPLIANCE ASSESSMENT"
Write-Host "============================================================"
Write-Host ""
Write-Host "This tool checks device configuration and security settings."
Write-Host "It does NOT collect passwords, browser history, personal files,"
Write-Host "saved credentials, personal email addresses, or PHI."
Write-Host ""

$EmployeeID = Read-Host "Enter your NextStep VA Employee ID"
if ([string]::IsNullOrWhiteSpace($EmployeeID)) {
    $EmployeeID = "NOT-PROVIDED"
}

$GeneratedDate = Get-Date

# Administrator status
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsAdmin = $false
}
$AdminStatus = if ($IsAdmin) { "Yes" } else { "No - some checks may show REVIEW" }

# ------------------------------------------------------------
# DEVICE ID (privacy-preserving hash, not raw serial)
# ------------------------------------------------------------

$MachineGuid = ""
try {
    $MachineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction Stop).MachineGuid
} catch {}

$BiosSerialForId = ""
try {
    $BiosSerialForId = (Get-CimInstance Win32_BIOS | Select-Object -First 1).SerialNumber
} catch {}

$RawDeviceIdentity = "$MachineGuid|$BiosSerialForId|$env:COMPUTERNAME"
$DeviceHash = Get-Sha256Text $RawDeviceIdentity
$DeviceID = "NSVA-" + $DeviceHash.Substring(0,16).ToUpperInvariant()

# ------------------------------------------------------------
# USER / ACCOUNT SUMMARY
# ------------------------------------------------------------

$CurrentWindowsUser = "$env:USERDOMAIN\$env:USERNAME"
$LocalUserCount = "Not available"
try {
    $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"
    $LocalUserCount = @($localUsers).Count
} catch {}

# ------------------------------------------------------------
# HARDWARE CONFIGURATION
# ------------------------------------------------------------

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
$baseBoard = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

$ComputerName = $env:COMPUTERNAME
$Manufacturer = if ($cs.Manufacturer) { $cs.Manufacturer } else { "Not available" }
$Model = if ($cs.Model) { $cs.Model } else { "Not available" }
$Processor = if ($cpu.Name) { $cpu.Name.Trim() } else { "Not available" }
$CpuCores = if ($cpu.NumberOfCores) { $cpu.NumberOfCores } else { "Not available" }
$CpuLogical = if ($cpu.NumberOfLogicalProcessors) { $cpu.NumberOfLogicalProcessors } else { "Not available" }

$RamGB = 0
try { $RamGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } catch {}
$RamStatus = if ($RamGB -ge 8) { "PASS" } else { "FAIL" }

$StorageTotalGB = "Not available"
$StorageFreeGB = "Not available"
if ($disk) {
    $StorageTotalGB = [math]::Round($disk.Size / 1GB, 1)
    $StorageFreeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
}

$BiosVersion = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion } else { "Not available" }
$BaseBoardModel = if ($baseBoard.Product) { $baseBoard.Product } else { "Not available" }
$SystemType = if ($cs.SystemType) { $cs.SystemType } else { "Not available" }

# ------------------------------------------------------------
# OPERATING SYSTEM / UPDATES
# ------------------------------------------------------------

$OSCaption = if ($os.Caption) { $os.Caption } else { "Not available" }
$OSVersion = if ($os.Version) { $os.Version } else { "Not available" }
$OSBuild = if ($os.BuildNumber) { $os.BuildNumber } else { "Not available" }
$OSInstallDate = SafeDate $os.InstallDate
$LastBoot = SafeDate $os.LastBootUpTime

$LastUpdate = "Not available"
$LastUpdateId = "Not available"
try {
    $hotfix = Get-HotFix | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1
    if ($hotfix) {
        $LastUpdate = ([datetime]$hotfix.InstalledOn).ToString("yyyy-MM-dd")
        $LastUpdateId = $hotfix.HotFixID
    }
} catch {}

$WindowsUpdateService = "Not available"
try {
    $wu = Get-Service -Name wuauserv -ErrorAction Stop
    $WindowsUpdateService = "$($wu.Status) / StartType: $($wu.StartType)"
} catch {}

# ------------------------------------------------------------
# SECURITY - FIREWALL
# ------------------------------------------------------------

$FirewallDetail = "Not available"
$FirewallStatus = "REVIEW"
try {
    $profiles = Get-NetFirewallProfile
    if ($profiles) {
        $FirewallDetail = ($profiles | ForEach-Object {
            "$($_.Name): " + $(if ($_.Enabled) { "Enabled" } else { "Disabled" })
        }) -join " | "
        if (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0) {
            $FirewallStatus = "PASS"
        } else {
            $FirewallStatus = "FAIL"
        }
    }
} catch {}

# ------------------------------------------------------------
# SECURITY - ANTIVIRUS / DEFENDER
# ------------------------------------------------------------

$DefenderDetail = "Not available"
$DefenderStatus = "REVIEW"
$DefenderDefinitions = "Not available"
$DefenderLastFullScan = "Not available"
$DetectedAV = "Not available"

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $DefenderDetail = "Antivirus: $($mp.AntivirusEnabled) | Real-time: $($mp.RealTimeProtectionEnabled)"
    if ($mp.AntivirusSignatureLastUpdated) {
        $DefenderDefinitions = SafeDate $mp.AntivirusSignatureLastUpdated
    }
    if ($mp.FullScanEndTime) {
        $DefenderLastFullScan = SafeDate $mp.FullScanEndTime
    } else {
        $DefenderLastFullScan = "Never / not reported"
    }

    if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
        $DefenderStatus = "PASS"
    } else {
        $DefenderStatus = "FAIL"
    }
} catch {}

try {
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct -ErrorAction Stop
    if ($avProducts) {
        $DetectedAV = (($avProducts | Select-Object -ExpandProperty displayName -Unique) -join ", ")
    }
} catch {}

# If Defender is not active but another AV exists, do not call it an automatic failure.
if ($DefenderStatus -eq "FAIL" -and $DetectedAV -ne "Not available" -and $DetectedAV -notmatch "Windows Defender") {
    $DefenderStatus = "REVIEW"
    $DefenderDetail += " | Third-party AV detected; manual verification recommended"
}

# ------------------------------------------------------------
# SECURITY - BITLOCKER / DEVICE ENCRYPTION
# ------------------------------------------------------------

$EncryptionStatus = "REVIEW"
$EncryptionDetail = "Not available"
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
    if ($bl) {
        $prot = [string]$bl.ProtectionStatus
        $volStatus = [string]$bl.VolumeStatus
        $pct = $bl.EncryptionPercentage
        $EncryptionDetail = "Protection: $prot | Volume: $volStatus | Encrypted: $pct%"
        if ($prot -eq "On" -or $prot -eq "1") {
            $EncryptionStatus = "PASS"
        } else {
            $EncryptionStatus = "FAIL"
        }
    }
} catch {
    try {
        $mbde = & manage-bde.exe -status C: 2>$null | Out-String
        if ($mbde -match "Protection Status:\s+Protection On") {
            $EncryptionStatus = "PASS"
            $EncryptionDetail = "Protection On (manage-bde)"
        } elseif ($mbde -match "Protection Status:\s+Protection Off") {
            $EncryptionStatus = "FAIL"
            $EncryptionDetail = "Protection Off (manage-bde)"
        } else {
            $EncryptionDetail = "Could not determine encryption state"
        }
    } catch {}
}

# ------------------------------------------------------------
# SECURITY - TPM / SECURE BOOT
# ------------------------------------------------------------

$TPMStatus = "REVIEW"
$TPMDetail = "Not available"
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm) {
        $TPMDetail = "Present: $($tpm.TpmPresent) | Ready: $($tpm.TpmReady) | Enabled: $($tpm.TpmEnabled)"
        if ($tpm.TpmPresent -and $tpm.TpmReady) { $TPMStatus = "PASS" }
        elseif (-not $tpm.TpmPresent) { $TPMStatus = "FAIL" }
    }
} catch {}

$SecureBootStatus = "REVIEW"
$SecureBootDetail = "Not available"
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    $SecureBootDetail = [string]$sb
    if ($sb -eq $true) { $SecureBootStatus = "PASS" }
    else { $SecureBootStatus = "FAIL" }
} catch {
    $SecureBootDetail = "Unsupported or requires elevated privileges"
}

# ------------------------------------------------------------
# AUTO-LOCK / SCREEN SECURITY
# ------------------------------------------------------------

$ScreenLockStatus = "REVIEW"
$ScreenLockDetail = "Not clearly configured"

# Prefer machine inactivity policy if set.
try {
    $policy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -ErrorAction Stop
    $secs = [int]$policy.InactivityTimeoutSecs
    if ($secs -gt 0) {
        $mins = [math]::Round($secs / 60, 1)
        $ScreenLockDetail = "Machine inactivity timeout: $mins minute(s)"
        if ($secs -le 900) { $ScreenLockStatus = "PASS" } else { $ScreenLockStatus = "FAIL" }
    }
} catch {}

# Fallback to current-user secure screensaver settings.
if ($ScreenLockStatus -eq "REVIEW") {
    try {
        $desk = Get-ItemProperty "HKCU:\Control Panel\Desktop"
        $active = [string]$desk.ScreenSaveActive
        $secure = [string]$desk.ScreenSaverIsSecure
        $timeout = 0
        [void][int]::TryParse([string]$desk.ScreenSaveTimeOut, [ref]$timeout)
        if ($active -eq "1" -and $secure -eq "1" -and $timeout -gt 0) {
            $mins = [math]::Round($timeout / 60, 1)
            $ScreenLockDetail = "Secure screensaver lock: $mins minute(s)"
            if ($timeout -le 900) { $ScreenLockStatus = "PASS" } else { $ScreenLockStatus = "FAIL" }
        }
    } catch {}
}

# ------------------------------------------------------------
# STORAGE SENSE
# ------------------------------------------------------------

$StorageSense = "Not available"
try {
    $ss = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
    $p = $ss.PSObject.Properties["01"]
    if ($p) {
        $StorageSense = if ([int]$p.Value -eq 1) { "Enabled" } else { "Disabled" }
    }
} catch {}

# ------------------------------------------------------------
# BROWSERS - VERSION ONLY, NO PROFILE/EMAIL/HISTORY COLLECTION
# ------------------------------------------------------------

$ChromeVersion = Get-BrowserVersion @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)

$EdgeVersion = Get-BrowserVersion @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)

$FirefoxVersion = Get-BrowserVersion @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
)

# ------------------------------------------------------------
# NETWORK - MINIMAL DATA ONLY
# ------------------------------------------------------------

$NetworkAdapter = "Not available"
$ConnectionType = "Not available"
try {
    $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 3
    if ($activeAdapters) {
        $NetworkAdapter = (($activeAdapters | ForEach-Object { $_.InterfaceDescription }) -join " | ")
        $names = (($activeAdapters | ForEach-Object { $_.Name }) -join " | ")
        if ($names -match "Wi-?Fi|Wireless|WLAN") { $ConnectionType = "Wi-Fi / Wireless" }
        elseif ($names -match "Ethernet") { $ConnectionType = "Ethernet" }
        else { $ConnectionType = "Connected adapter detected" }
    }
} catch {}

# ------------------------------------------------------------
# PERIPHERALS
# ------------------------------------------------------------

$CameraStatus = "Not detected"
$MicrophoneStatus = "Not detected"
$AudioStatus = "Not detected"

try {
    $cams = Get-PnpDevice -Class Camera -Status OK -ErrorAction Stop
    if ($cams) { $CameraStatus = "Detected" }
} catch {
    try {
        $cams = Get-CimInstance Win32_PnPEntity | Where-Object {
            $_.Name -match "camera|webcam" -and $_.Status -eq "OK"
        }
        if ($cams) { $CameraStatus = "Detected" }
    } catch {}
}

try {
    $mics = Get-PnpDevice -Class AudioEndpoint -Status OK -ErrorAction Stop |
        Where-Object { $_.FriendlyName -match "microphone|mic" }
    if ($mics) { $MicrophoneStatus = "Detected" }
} catch {}

try {
    $sound = Get-CimInstance Win32_SoundDevice | Where-Object { $_.Status -eq "OK" }
    if ($sound) { $AudioStatus = "Detected" }
} catch {}

# ------------------------------------------------------------
# INTERNAL BASELINE SUMMARY
# Only criteria explicitly used here:
# - RAM >= 8 GB
# - Firewall enabled on all profiles
# - Disk encryption enabled
# - Active antivirus / real-time protection verified
# - Secure automatic screen lock <= 15 minutes
#
# HIPAA itself does not prescribe this exact checklist.
# ------------------------------------------------------------

$CoreStatuses = @(
    $RamStatus,
    $FirewallStatus,
    $EncryptionStatus,
    $DefenderStatus,
    $ScreenLockStatus
)

if ($CoreStatuses -contains "FAIL") {
    $OverallStatus = "ACTION REQUIRED"
    $OverallClass = "fail"
} elseif ($CoreStatuses -contains "REVIEW") {
    $OverallStatus = "MANUAL REVIEW"
    $OverallClass = "review"
} else {
    $OverallStatus = "PASS"
    $OverallClass = "pass"
}

# ------------------------------------------------------------
# EMBEDDED NEXTSTEP VA LOGO
# ------------------------------------------------------------

$LogoBase64 = "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"
$LogoDataUri = "data:image/png;base64,$LogoBase64"

# ------------------------------------------------------------
# OUTPUT PATH / FILE NAME
# ------------------------------------------------------------

$Downloads = Get-DownloadsPath
$SafeEmployeeID = ($EmployeeID -replace '[^A-Za-z0-9_-]', '_')
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$ReportName = "${SafeEmployeeID}_NextStepVA_Device_Compliance_${Timestamp}.html"
$ReportPath = Join-Path $Downloads $ReportName

# ------------------------------------------------------------
# HTML REPORT
# ------------------------------------------------------------

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NextStep VA Device & Security Compliance Report</title>
<style>
    :root {
        --navy: #183b7a;
        --blue: #1fa6da;
        --teal: #086b73;
        --light: #f4f7fb;
        --line: #d9e1ea;
        --text: #1b2430;
        --muted: #5f6b78;
        --pass-bg: #e8f7ee;
        --pass-fg: #176b37;
        --fail-bg: #fdecec;
        --fail-fg: #a12626;
        --review-bg: #fff4d8;
        --review-fg: #8a5a00;
        --info-bg: #edf2f7;
        --info-fg: #425466;
    }

    * { box-sizing: border-box; }

    body {
        margin: 0;
        background: #ffffff;
        color: var(--text);
        font-family: "Segoe UI", Arial, Helvetica, sans-serif;
        font-size: 14px;
    }

    .page {
        width: 100%;
        margin: 0 auto;
        padding: 28px 34px 40px;
    }

    .header {
        text-align: center;
        padding: 4px 0 14px;
    }

    .logo {
        width: 118px;
        height: auto;
        display: block;
        margin: 0 auto 4px;
    }

    .title {
        margin: 0;
        color: var(--teal);
        font-size: 25px;
        line-height: 1.12;
        letter-spacing: .3px;
        text-transform: uppercase;
        font-weight: 800;
    }

    .subtitle {
        margin: 3px 0 0;
        color: var(--navy);
        font-size: 13px;
        font-weight: 700;
        letter-spacing: .7px;
        text-transform: uppercase;
    }

    .meta {
        margin: 14px 0 8px;
        line-height: 1.55;
        font-size: 12px;
    }

    .notice {
        color: #a22a2a;
        font-size: 11px;
        font-style: italic;
        margin: 6px 0 12px;
    }

    .section {
        margin-top: 8px;
        border: 1px solid var(--line);
    }

    .section-title {
        margin: 0;
        padding: 7px 10px;
        background: var(--teal);
        color: white;
        font-size: 13px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: .2px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
    }

    td {
        padding: 7px 10px;
        vertical-align: top;
        border-top: 1px solid var(--line);
        word-break: break-word;
    }

    tr:first-child td { border-top: none; }

    td.label {
        width: 34%;
        background: #f7f9fc;
        font-weight: 700;
    }

    td.value {
        width: 66%;
    }

    .status {
        display: inline-block;
        min-width: 66px;
        padding: 2px 8px;
        border-radius: 999px;
        text-align: center;
        font-size: 11px;
        font-weight: 800;
        margin-left: 6px;
    }

    .pass { background: var(--pass-bg); color: var(--pass-fg); }
    .fail { background: var(--fail-bg); color: var(--fail-fg); }
    .review { background: var(--review-bg); color: var(--review-fg); }
    .info { background: var(--info-bg); color: var(--info-fg); }

    .summary {
        margin-top: 12px;
        padding: 16px;
        border: 2px solid var(--teal);
        text-align: center;
    }

    .summary-label {
        color: var(--muted);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: .8px;
        font-weight: 700;
    }

    .summary-status {
        margin-top: 5px;
        font-size: 24px;
        font-weight: 900;
    }

    .privacy {
        margin-top: 12px;
        padding: 12px 14px;
        background: #f7f9fc;
        border-left: 4px solid var(--blue);
        line-height: 1.5;
        font-size: 11px;
    }

    .footer {
        margin-top: 18px;
        text-align: center;
        color: var(--muted);
        font-size: 10px;
        line-height: 1.5;
    }

    @media print {
        body { background: white; }
        .page { padding: 12px; }
        .section { break-inside: avoid; }
        .privacy { break-inside: avoid; }
    }
</style>
</head>

<body>
<div class="page">

    <div class="header">
        <img class="logo" src="$LogoDataUri" alt="NextStep VA logo">
        <h1 class="title">NextStep VA</h1>
        <div class="subtitle">Device & Security Compliance Report</div>
    </div>

    <div class="meta">
        <strong>Generated:</strong> $(HtmlEncode ($GeneratedDate.ToString("yyyy-MM-dd HH:mm:ss")))<br>
        <strong>Employee ID:</strong> $(HtmlEncode $EmployeeID)<br>
        <strong>Device ID:</strong> $(HtmlEncode $DeviceID)<br>
        <strong>Administrator session:</strong> $(HtmlEncode $AdminStatus)
    </div>

    <div class="notice">
        This report is intended for NextStep VA onboarding/security review. It supports internal security verification and does not, by itself, certify HIPAA compliance.
    </div>

    <div class="section">
        <div class="section-title">User / Account Summary</div>
        <table>
            <tr><td class="label">Current Windows Account</td><td class="value">$(HtmlEncode $CurrentWindowsUser)</td></tr>
            <tr><td class="label">Local Windows Accounts</td><td class="value">Count: $(HtmlEncode $LocalUserCount) &mdash; account names intentionally not collected</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Hardware Configuration</div>
        <table>
            <tr><td class="label">Computer Name</td><td class="value">$(HtmlEncode $ComputerName)</td></tr>
            <tr><td class="label">Manufacturer</td><td class="value">$(HtmlEncode $Manufacturer)</td></tr>
            <tr><td class="label">Model</td><td class="value">$(HtmlEncode $Model)</td></tr>
            <tr><td class="label">System Type</td><td class="value">$(HtmlEncode $SystemType)</td></tr>
            <tr><td class="label">Processor</td><td class="value">$(HtmlEncode $Processor)</td></tr>
            <tr><td class="label">CPU Cores / Logical Processors</td><td class="value">$(HtmlEncode $CpuCores) / $(HtmlEncode $CpuLogical)</td></tr>
            <tr><td class="label">Memory (RAM)</td><td class="value">$(HtmlEncode "$RamGB GB") $(StatusHtml $RamStatus) &nbsp; Minimum: 8 GB</td></tr>
            <tr><td class="label">Storage (C:)</td><td class="value">Total: $(HtmlEncode "$StorageTotalGB GB") &nbsp; | &nbsp; Free: $(HtmlEncode "$StorageFreeGB GB")</td></tr>
            <tr><td class="label">BIOS Version</td><td class="value">$(HtmlEncode $BiosVersion)</td></tr>
            <tr><td class="label">Baseboard</td><td class="value">$(HtmlEncode $BaseBoardModel)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Operating System</div>
        <table>
            <tr><td class="label">OS Edition</td><td class="value">$(HtmlEncode $OSCaption)</td></tr>
            <tr><td class="label">OS Version</td><td class="value">$(HtmlEncode $OSVersion)</td></tr>
            <tr><td class="label">Build Number</td><td class="value">$(HtmlEncode $OSBuild)</td></tr>
            <tr><td class="label">Windows Installed</td><td class="value">$(HtmlEncode $OSInstallDate)</td></tr>
            <tr><td class="label">Last Boot</td><td class="value">$(HtmlEncode $LastBoot)</td></tr>
            <tr><td class="label">Latest Installed Update</td><td class="value">$(HtmlEncode $LastUpdate) &nbsp; $(HtmlEncode $LastUpdateId)</td></tr>
            <tr><td class="label">Windows Update Service</td><td class="value">$(HtmlEncode $WindowsUpdateService)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Security & Compliance</div>
        <table>
            <tr><td class="label">Disk Encryption (BitLocker / Device Encryption)</td><td class="value">$(HtmlEncode $EncryptionDetail) $(StatusHtml $EncryptionStatus)</td></tr>
            <tr><td class="label">Windows Firewall</td><td class="value">$(HtmlEncode $FirewallDetail) $(StatusHtml $FirewallStatus)</td></tr>
            <tr><td class="label">Native Security / Real-Time Protection</td><td class="value">$(HtmlEncode $DefenderDetail) $(StatusHtml $DefenderStatus)</td></tr>
            <tr><td class="label">Detected Antivirus Product(s)</td><td class="value">$(HtmlEncode $DetectedAV)</td></tr>
            <tr><td class="label">Antivirus Definitions Updated</td><td class="value">$(HtmlEncode $DefenderDefinitions)</td></tr>
            <tr><td class="label">Last Full Antivirus Scan</td><td class="value">$(HtmlEncode $DefenderLastFullScan)</td></tr>
            <tr><td class="label">TPM</td><td class="value">$(HtmlEncode $TPMDetail) $(StatusHtml $TPMStatus)</td></tr>
            <tr><td class="label">Secure Boot</td><td class="value">$(HtmlEncode $SecureBootDetail) $(StatusHtml $SecureBootStatus)</td></tr>
            <tr><td class="label">Auto-Lock / Screen Security</td><td class="value">$(HtmlEncode $ScreenLockDetail) $(StatusHtml $ScreenLockStatus)</td></tr>
            <tr><td class="label">Storage Sense</td><td class="value">$(HtmlEncode $StorageSense)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Browser Information</div>
        <table>
            <tr><td class="label">Google Chrome</td><td class="value">$(HtmlEncode $ChromeVersion)</td></tr>
            <tr><td class="label">Microsoft Edge</td><td class="value">$(HtmlEncode $EdgeVersion)</td></tr>
            <tr><td class="label">Mozilla Firefox</td><td class="value">$(HtmlEncode $FirefoxVersion)</td></tr>
            <tr><td class="label">Browser Profiles</td><td class="value">Not collected (privacy / data minimization)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Network & Peripherals</div>
        <table>
            <tr><td class="label">Active Network Adapter</td><td class="value">$(HtmlEncode $NetworkAdapter)</td></tr>
            <tr><td class="label">Connection Type</td><td class="value">$(HtmlEncode $ConnectionType)</td></tr>
            <tr><td class="label">Camera</td><td class="value">$(HtmlEncode $CameraStatus)</td></tr>
            <tr><td class="label">Microphone</td><td class="value">$(HtmlEncode $MicrophoneStatus)</td></tr>
            <tr><td class="label">Audio Device</td><td class="value">$(HtmlEncode $AudioStatus)</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Internal Baseline Summary</div>
        <table>
            <tr><td class="label">RAM (8 GB minimum)</td><td class="value">$(StatusHtml $RamStatus)</td></tr>
            <tr><td class="label">Firewall</td><td class="value">$(StatusHtml $FirewallStatus)</td></tr>
            <tr><td class="label">Disk Encryption</td><td class="value">$(StatusHtml $EncryptionStatus)</td></tr>
            <tr><td class="label">Antivirus / Real-Time Protection</td><td class="value">$(StatusHtml $DefenderStatus)</td></tr>
            <tr><td class="label">Automatic Screen Lock (15 min or less)</td><td class="value">$(StatusHtml $ScreenLockStatus)</td></tr>
        </table>
    </div>

    <div class="summary">
        <div class="summary-label">NextStep VA Internal Device Baseline</div>
        <div class="summary-status $OverallClass">$(HtmlEncode $OverallStatus)</div>
    </div>

    <div class="privacy">
        <strong>Privacy / Data Minimization Notice:</strong><br>
        This assessment collects device configuration and security information for onboarding and security review.
        It does not intentionally collect passwords, saved credentials, browser history, browser profile names,
        personal email addresses, personal documents, medical information, or PHI. Device reports should be handled
        as sensitive internal records and stored only in approved NextStep VA systems.
    </div>

    <div class="footer">
        NextStep VA IT Department<br>
        Remote Workforce Device & Security Assessment<br>
        Report file: $(HtmlEncode $ReportName)
    </div>

</div>
</body>
</html>
"@

# ------------------------------------------------------------
# SAVE / OPEN
# ------------------------------------------------------------

$html | Out-File -FilePath $ReportPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "============================================================"
Write-Host " NextStep VA Device Assessment Complete"
Write-Host "============================================================"
Write-Host ""
Write-Host "Report saved to:"
Write-Host $ReportPath
Write-Host ""
Write-Host "Please send the generated HTML file using the approved"
Write-Host "NextStep VA submission method."
Write-Host ""

try {
    Start-Process $ReportPath
} catch {}

try {
    Start-Process explorer.exe -ArgumentList "/select,`"$ReportPath`""
} catch {}

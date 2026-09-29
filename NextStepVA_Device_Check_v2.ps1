#requires -Version 5.1
# NextStep VA Device Check v2

$ErrorActionPreference="SilentlyContinue"

function Safe($v){if($null -eq $v -or "$v" -eq ""){"NOT DETECTED"}else{[System.Net.WebUtility]::HtmlEncode([string]$v)}}
function Badge($s){if($s -eq "PASS"){"PASS"}elseif($s -eq "FAIL"){"FAIL"}else{"REVIEW"}}

Clear-Host
Write-Host "NEXTSTEP VA DEVICE CHECK v2"

$EmployeeID=Read-Host "Enter your NextStep VA Employee ID"
if(!$EmployeeID){$EmployeeID="NOT-PROVIDED"}

$ComputerName=$env:COMPUTERNAME

$cs=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem

$Manufacturer=$cs.Manufacturer
$Model=$cs.Model
$RAM=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
$OS=$os.Caption
$Build=$os.BuildNumber

$RamStatus=if($RAM -ge 8){"PASS"}else{"FAIL"}

$FirewallStatus="REVIEW"
$FirewallDetail="NOT DETECTED"
try{
$f=Get-NetFirewallProfile
$FirewallDetail=($f|ForEach-Object{"$($_.Name):$($_.Enabled)"}) -join ", "
if(@($f|Where-Object {!$_.Enabled}).Count -eq 0){$FirewallStatus="PASS"}else{$FirewallStatus="FAIL"}
}catch{}

$AVStatus="REVIEW"
$AVDetail="NOT DETECTED"
try{
$d=Get-MpComputerStatus
$AVDetail="Antivirus:$($d.AntivirusEnabled) RealTime:$($d.RealTimeProtectionEnabled)"
if($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled){$AVStatus="PASS"}
}catch{}

$Report="$env:USERPROFILE\Downloads\NextStepVA_Device_Compliance_Report.html"

$html=@"
<html>
<head><title>NextStep VA Report</title>
<style>body{font-family:Arial;background:#f4f6f8;margin:30px}.box{background:white;padding:20px;margin:10px;border-radius:8px}td{padding:8px}</style>
</head>
<body>
<div class='box'>
<h1>NextStep VA</h1>
<h2>Device Compliance Report</h2>
<p>Employee ID: $(Safe $EmployeeID)</p>
<p>Generated: $(Get-Date)</p>
</div>

<div class='box'>
<h3>Hardware</h3>
<table>
<tr><td>Computer Name</td><td>$(Safe $ComputerName)</td></tr>
<tr><td>Manufacturer</td><td>$(Safe $Manufacturer)</td></tr>
<tr><td>Model</td><td>$(Safe $Model)</td></tr>
<tr><td>RAM</td><td>$(Safe "$RAM GB") $(Badge $RamStatus)</td></tr>
</table>
</div>

<div class='box'>
<h3>Operating System</h3>
<table>
<tr><td>OS</td><td>$(Safe $OS)</td></tr>
<tr><td>Build</td><td>$(Safe $Build)</td></tr>
</table>
</div>

<div class='box'>
<h3>Security</h3>
<table>
<tr><td>Firewall</td><td>$(Safe $FirewallDetail) $(Badge $FirewallStatus)</td></tr>
<tr><td>Antivirus</td><td>$(Safe $AVDetail) $(Badge $AVStatus)</td></tr>
</table>
</div>
</body></html>
"@

$html | Out-File $Report -Encoding UTF8 -Force

Write-Host "Report saved:"
Write-Host $Report

Start-Process $Report

# NextStep VA Device Compliance Checker

## Overview

NextStep VA Device Compliance Checker is a PowerShell-based Windows device assessment tool designed to collect system configuration and security information for internal onboarding and compliance review.

The tool generates an HTML device compliance report that can be reviewed and submitted securely.

---

## Features

### Hardware Assessment
- Computer Name
- Manufacturer
- Device Model
- Processor Information
- Memory (RAM)
- Storage Information
- BIOS Version
- Baseboard Information

### Operating System Checks
- Windows Edition
- Windows Version
- Build Number
- Installation Date
- Last Boot Time
- Windows Update Information

### Security & Compliance Checks
- BitLocker / Device Encryption
- Windows Firewall Status
- Antivirus / Real-Time Protection
- TPM Status
- Secure Boot Status
- Screen Lock Configuration
- Storage Sense

### Network & Peripheral Checks
- Network Adapter
- Connection Type
- Camera Detection
- Microphone Detection
- Audio Device Detection

### Privacy Protection
The assessment does not intentionally collect:
- Passwords
- Saved credentials
- Browser history
- Personal documents
- Personal email addresses
- Medical information or PHI

---

## Usage

Run PowerShell as Administrator.

Execute:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm 'https://raw.githubusercontent.com/calvintoyzxc/NextStepVA-Device-Check/main/NextStepVA_Device_Check.ps1' -OutFile $env:TEMP\NextStepVA_Device_Check.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\NextStepVA_Device_Check.ps1"

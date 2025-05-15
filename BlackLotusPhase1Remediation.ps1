<#
.SYNOPSIS
This script will complete "Phase 1" (steps 1 & 2) of remediation steps for the BLackLotus aka CVE-2023-24932

.DESCRIPTION
This script will perform steps 1 & 2 as follows:
- Step 1: Install the updated certificate definitions to the DB
- Step 2: Update the Boot Manager on your device

When complete, the device will still be able to boot using media signed with the old CA. Phase 2 must be completed as well in order to complete mitigate CVE-2023-24932.

This script was designed to be able to run in multiple ways, such as:
- ConfigMgr CI
- ConfigMgr Run Script
- Intune Remediation
- Ad Hoc/On Demand

.EXAMPLE

.\BlackLotusPhase1Remediation.ps1

.NOTES
Version: 1.0
Author: Anthony Fontanez
Initial creation date: 2025-05-14
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
Param(
)

function Write-Log {
    # Source: https://www.ephingadmin.com/powershell-cmtrace-log-function/
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$Component,
        [Parameter(Mandatory = $true)]
        [ValidateSet('1', '2', '3')]
        [int]$Type,
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    #Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    $Time = Get-Date -Format 'HH:mm:ss.ffffff'
    $Date = Get-Date -Format 'MM-dd-yyyy'
    $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}

# Create log file if it does not exist
$LogFile = "$env:TEMP\BlackLotusPhase1Remediation.log"
if (-not (Test-Path -Path $LogFile)) {
    New-Item -Path $LogFile
}

Write-Log -Message 'Starting BlackLotus Phase 1 Remediation' -Component 'Pre-Check' -Type 1 -LogFile $LogFile

# Check if running as CcmExec to adjust script output for ConfigMgr use
$ParentProcessName = (Get-Process -Id ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID").ParentProcessId)).ProcessName
if ($ParentProcessName -eq 'CcmExec') {
    $RunningAsCcmExec = $true
}

# Check if we are already in the expected state, and exit if so
$WindowsUEFICA2023Capable = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name WindowsUEFICA2023Capable -ErrorAction Ignore
if ($WindowsUEFICA2023Capable -eq 2) {
    Write-Log -Message '"Windows UEFI CA 2023" certificate is in the DB and the system is starting from the 2023 signed boot manager' -Component 'Pre-Check' -Type 1 -LogFile $LogFile
    if ($RunningAsCcmExec) {
        return $true
    }
    else {
        Write-Output '"Windows UEFI CA 2023" certificate is in the DB and the system is starting from the 2023 signed boot manager'
        exit 0
    }
}

# Continue with remediation if WindowsUEFICA2023Capable ne 2

# Get current Secure Boot DB information
$SecureBootDB = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)

# Step 1: Install the updated certificate definitions to the DB if not already preset
if ($SecureBootDB -notmatch 'Windows UEFI CA 2023') {
    Write-Log -Message 'Updated certificate definitions not present in DB' -Component 'Step 1' -Type 1 -LogFile $LogFile
    # Set AvailableUpdates to 0x40 and trigger scheduled task to update the Secure Boot DB
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot -Name AvailableUpdates -Value 0x40 -Force
    Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
    # Wait for up to 2 minutes for event 1026 to indicate update was applied
    for ($i = 0; $i -lt 12; $i++) {
        # Event ID 1026: "Secure Boot Db update applied successfully"
        $event1036 = Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Id -eq 1036}
        if (-not $event1036) {
            Start-Sleep -Seconds 10
        }
    }
    if ($event1036) {
        # Verify Step 1 is complete
        $WindowsUEFICA2023Capable = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name WindowsUEFICA2023Capable -ErrorAction Ignore
        # If WindowsUEFICA2023Capable did not change from 0 to 1, exit, else we continue to step 2
        if ($WindowsUEFICA2023Capable -ne 1) {
            Write-Log -Message 'Secure Boot DB update did not complete' -Component 'Step 1' -Type 2 -LogFile $LogFile
            if ($RunningAsCcmExec) {
                return $false
            }
            else {
                Write-Output 'Secure Boot DB update did not complete'
                exit 1
            }
        }
        else {
            Write-Log -Message 'Secure Boot DB update complete' -Component 'Step 1' -Type 1 -LogFile $LogFile
        }
    }
    else {
        Write-Log -Message 'Secure Boot DB update did not complete' -Component 'Step 1' -Type 2 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $false
        }
        else {
            Write-Output 'Secure Boot DB update did not complete'
            exit 1
        }
    }
}

# Step 2: Update the Boot Manager on your device
if ($SecureBootDB -match 'Windows UEFI CA 2023') {
    Write-Log -Message 'Updated certificate definitions present in DB, beginning boot manager update' -Component 'Step 2' -Type 1 -LogFile $LogFile
    # Set AvailableUpdates to 0x100 and trigger scheduled task to update the boot manager
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot -Name AvailableUpdates -Value 0x100 -Force
    Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
    # Wait for up to 2 minutes for event 1799 or 1800 to indicate updated boot manager was installed or a reboot is required
    for ($i = 0; $i -lt 12; $i++) {
        # Event ID 1799: "Boot Manager signed with Windows UEFI CA 2023 was installed successfully"
        $event1799 = Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Id -eq 1799}
        # Event ID 1800: "Reboot needed before continuing"
        $event1800 = Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Id -eq 1800}
        if (-not $event1799 -and -not $event1800) {
            Start-Sleep -Seconds 10
        }
        else {
            break
        }
    }
    # If only event IF 1800 is logged, a reboot is required
    if ($event1800 -and -not $event1799) {
        Write-Log -Message 'Reboot needed before continuing' -Component 'Step 2' -Type 2 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $false
        }
        else {
            Write-Output 'Reboot needed before continuing'
            exit 1
        }
    }
    # If event ID 1799 is logged, we can now verify the boot manager update was completed successfully
    elseif ($event1799) {
        Write-Log -Message 'Verifying boot manager update is complete' -Component 'Step 2' -Type 1 -LogFile $LogFile
        # Verify Step 2 is complete, hopefully doing the following doesn't trigger any AV/EDR products!
        mountvol s: /s
        # Get-AuthenticodeSignature will not work for our purposes, see the following links:
        # https://github.com/PowerShell/PowerShell/issues/8401#issuecomment-783993634
        # https://github.com/PowerShell/PowerShell/issues/23820
        # Good: "CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US"
        # Bad: "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile('S:\EFI\Microsoft\Boot\bootmgfw.efi')
        mountvol s: /d
        # If certificate issuer is NOT the 2023 CA, the update did not complete successfully
        if ($cert.Issuer -ne 'CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US') {
            Write-Log -Message 'bootmgr.efi is not signed with 2023 CA' -Component 'Step 2' -Type 2 -LogFile $LogFile
            if ($RunningAsCcmExec) {
                return $false
            }
            else {
                Write-Output 'bootmgr.efi is not signed with 2023 CA'
                exit 1
            }
        }
        else {
            Write-Log -Message 'bootmgr.efi is signed with 2023 CA' -Component 'Step 2' -Type 1 -LogFile $LogFile
            if ($RunningAsCcmExec) {
                return $true
            }
            else {
                Write-Output 'bootmgr.efi is signed with 2023 CA'
                exit 0
            }
        }
    }
    # If neither event 1799 or 1800 were logged, we will exit and try again later
    else {
        Write-Log -Message 'New signed boot manager installation not detected' -Component 'Step 2' -Type 2 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $false
        }
        else {
            Write-Output 'New signed boot manager installation not detected'
            exit 1
        }
    }
}

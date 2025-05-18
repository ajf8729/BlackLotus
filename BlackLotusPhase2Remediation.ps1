<#
.SYNOPSIS
This script will complete "Phase 2" (steps 3 & 4) of remediation steps for BlackLotus aka CVE-2023-24932

.DESCRIPTION
This script will perform steps 3 & 4 as follows:
- Step 1: Enable the revocation of the 2011 CA
- Step 2: Apply the SVN update to the firmware

When complete, the device will NO LONGER be able to boot using media signed with the old CA.

This script was designed to be able to run in multiple ways, such as:
- ConfigMgr CI
- ConfigMgr Run Script
- Intune Remediation
- Ad Hoc/On Demand

.EXAMPLE

.\BlackLotusPhase2Remediation.ps1

.NOTES
Version: 1.1
Author: Anthony Fontanez
Initial creation date: 2025-05-18
#>

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

# Check if running as CcmExec/WmiPrvSE to adjust script output for ConfigMgr use
$ParentProcessName = (Get-Process -Id ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID").ParentProcessId)).ProcessName
if ($ParentProcessName -eq 'CcmExec' -or $ParentProcessName -eq 'WmiPrvSE') {
    $RunningAsCcmExec = $true
}

# Verify device is ready for phase 2 remediation

$WindowsUEFICA2023Capable = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name WindowsUEFICA2023Capable -ErrorAction Ignore

# Check if we are already in expected state, and exit if so
if ($WindowsUEFICA2023Capable -ne 2) {
    if ($RunningAsCcmExec) {
        return $false
    }
    else {
        Write-Output 'Device not ready for BlackLotus Phase 2 remediation'
        exit 1
    }
}

# Get current Secure Boot DBX information
$SecureBootDBX = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes)

# Check if we are already in the expected state, and exit if so
if ($SecureBootDBX -match 'Microsoft Windows Production PCA 2011') {
    if ($RunningAsCcmExec) {
        return $true
    }
    else {
        Write-Output '"Microsoft Windows Production PCA 2011" certificate is in the DBX'
        exit 0
    }
}

# Create log file if it does not exist
$LogFile = "$env:TEMP\BlackLotusPhase2Remediation.log"
if (-not (Test-Path -Path $LogFile)) {
    New-Item -Path $LogFile
}

Write-Log -Message 'Starting BlackLotus Phase 2 Remediation' -Component 'Pre-Check' -Type 1 -LogFile $LogFile

# Continue with remediation if 2011 CA is not in the DBX

# Step 1: Enable revocation of the 2011 CA
if ($SecureBootDBX -notmatch 'Microsoft Windows Production PCA 2011') {
    Write-Log -Message 'Updated certificate revocation not present in DBX' -Component 'Step 1' -Type 1 -LogFile $LogFile
    # Set AvailableUpdates to 0x80 and trigger scheduled task to update the Secure Boot DBX
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot -Name AvailableUpdates -Value 0x80 -Force
    Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
    # Wait for up to 2 minutes for event ID 1037 to indicate update was applied, or event ID 1800 to indicate a reboot is required
    for ($i = 0; $i -lt 12; $i++) {
        # Event ID 1037: "Secure Boot Dbx update to revoke Microsoft Windows Production PCA 2011 is applied successfully"
        $event1037 = Get-WinEvent -LogName System -MaxEvents 1000 | Where-Object {$_.Id -eq 1037}
        # Event ID 1800: "Reboot needed before continuing"
        $event1800 = Get-WinEvent -LogName System -MaxEvents 1000 | Where-Object {$_.Id -eq 1800}
        if (-not $event1037 -and -not $event1800) {
            Start-Sleep -Seconds 10
        }
    }
    if ($event1800 -and -not $event1037) {
        Write-Log -Message 'Reboot needed before continuing' -Component 'Step 2' -Type 2 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $false
        }
        else {
            Write-Output 'Reboot needed before continuing'
            exit 1
        }
    }
    elseif ($event1037) {
        # Verify Step 1 is complete
        $SecureBootDBX = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes)
        # If 2011 CA is in the DBX, continue to step 2, otherwise exit as incomplete
        if ($SecureBootDBX -match 'Microsoft Windows Production PCA 2011') {
            Write-Log -Message 'Secure Boot DBX revocation complete' -Component 'Step 1' -Type 1 -LogFile $LogFile
        }
        else {
            Write-Log -Message 'Secure Boot DBX revocation did not complete' -Component 'Step 1' -Type 2 -LogFile $LogFile
            if ($RunningAsCcmExec) {
                return $false
            }
            else {
                Write-Output 'Secure Boot DBX revocation did not complete'
                exit 1
            }
        }
    }
    else {
        Write-Log -Message 'Secure Boot DBX revocation did not complete' -Component 'Step 1' -Type 2 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $false
        }
        else {
            Write-Output 'Secure Boot DBX revocation did not complete'
            exit 1
        }
    }
}

# Step 2: Apply the SVN update to the firmware
if ($SecureBootDBX -match 'Microsoft Windows Production PCA 2011') {
    Write-Log -Message 'Updated certificate revocation present in DBX, beginning SVN update' -Component 'Step 2' -Type 1 -LogFile $LogFile
    # Set AvailableUpdates to 0x200 and trigger scheduled task to update the boot manager
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot -Name AvailableUpdates -Value 0x200 -Force
    Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'
    # Wait for up to 2 minutes for event ID 1042 to indicate update was applied
    for ($i = 0; $i -lt 12; $i++) {
        # Event ID 1042: "Secure Boot Dbx update to revoke older Boot Manager SVNs is applied successfully"
        $event1042 = Get-WinEvent -LogName System -MaxEvents 1000 | Where-Object {$_.Id -eq 1042}
        if (-not $event1042) {
            Start-Sleep -Seconds 10
        }
    }
    if (-not $event1042) {
        Write-Log -Message 'SVN update is not complete' -Component 'Step 2' -Type 1 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $true
        }
        else {
            Write-Output 'SVN update is not complete'
            exit 0
        }
    }
    # There is currently no way to validate that the SVN update is complete. Here we just check to see that AvailableUpdates has returned to 0.
    for ($i = 0; $i -lt 12; $i++) {
        $AvailableUpdates = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot -Name AvailableUpdates -ErrorAction Ignore
        if ($AvailableUpdates -ne 0x0) {
            Start-Sleep -Seconds 10
        }
    }
    if ($AvailableUpdates -eq 0x0) {
        Write-Log -Message 'SVN update is complete' -Component 'Step 2' -Type 1 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $true
        }
        else {
            Write-Output 'SVN update is complete'
            exit 0
        }
    }
    else {
        Write-Log -Message 'SVN update is not complete' -Component 'Step 2' -Type 1 -LogFile $LogFile
        if ($RunningAsCcmExec) {
            return $true
        }
        else {
            Write-Output 'SVN update is not complete'
            exit 0
        }
    }
}

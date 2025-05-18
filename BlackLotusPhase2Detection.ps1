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

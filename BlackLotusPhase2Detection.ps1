# Check if running as CcmExec/WmiPrvSE to adjust script output for ConfigMgr use
$ParentProcessName = (Get-Process -Id ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID").ParentProcessId)).ProcessName
if ($ParentProcessName -eq 'CcmExec' -or $ParentProcessName -eq 'WmiPrvSE') {
    $RunningAsCcmExec = $true
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

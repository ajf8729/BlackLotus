# BlackLotus

BlackLotus aka CVE-2023-24932 Detection/Remediation Scripts for Intune, ConfigMgr, and generic use.

## General Notes

My remediation scripts do NOT initiate any reboots. These are designed to be run "over time", and eventually the device will report as compliant over its course of "natural" reboots, either via monthly updates, or user-initiated.

Feel free to open an issue or ping me on Discord in WinAdmins if you have any feedback.

## Phase 1: Installing the updated certificate definitions to the DB, and updating the Boot Manager on your device

The Phase 1 script will perform steps 1 & 2 from the published guidance, by setting the AvailableUpdates registry value to 0x40, starting the "\Microsoft\Windows\PI\Secure-Boot-Update" scheduled task, then setting it to 0x100 and running the scheduled task again. Validation is done between each step, and will be logged to C:\Windows\Temp\BlackLotusPhase1Remediation.log, as well as returned to Intune (if running the script as a remediation).

### ConfigMgr CI Use

If using this as a CI, you will need to put the remediation script contents into the detection script, and leave the remediation script empty, due to how CIs evaluate. Only use lines 34 (the start of the Write-Log function) to the end in the CI, as COnfigMgr doesn't seem like like having the CmdletBinding block.

If configured as a CI in ConfigMgr, the script will return true or false; use this to determine if the CI detection/remediation is successful or not.

### Ad-Hoc Use

The remediation script can also be run directly as admin if desired for testing. The remediation script includes the detection script at the top in order to exit out if it is already compliant to avoid issues with running the remediation script on-demand. The detection portion is checking the value of the WindowsUEFICA2023Capable registry item.

## Phase 2: Enabling the revocation and applying the SVN update to the firmware

Coming soon...

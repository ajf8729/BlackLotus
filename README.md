# BlackLotus

BlackLotus aka CVE-2023-24932 Detection/Remediation Scripts for Intune, ConfigMgr, and generic use

## Phase 1: Installing the updated certificate definitions to the DB, and updating the Boot Manager on your device

The Phase 1 script will perform steps 1 & 2 from the published guidance, by setting the AvailableUpdates registry value to 0x40, starting the "\Microsoft\Windows\PI\Secure-Boot-Update" scheduled task, then setting it to 0x100 and running the scheduled task again. Validation is done between each step, and will be logged to C:\Windows\Temp\BlackLotusPhase1Remediation.log, as well as returned to Intune (if running the script as a remediation).

If configured as a CI in ConfigMgr, the script will return true or false; use this to determine if the CI detection/remediation is successful or not.

The remediation script can also be run directly as admin if desired for testing. The remediation script includes the detection script at the top in order to exit out if it is already compliant to avoid issues with running the remediation script on-demand. The detection portion is checking the value of the WindowsUEFICA2023Capable registry item.

Feel free to open an issue or ping me on Discord in WinAdmins if you have any feedback.

## Phase 2: Enabling the revocation and applying the SVN update to the firmware

Coming soon...

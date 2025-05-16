# All Things Bitlocker

## Prereqs

### === Management Scripts Options ===
#### RMM Input Options
- $MountPoint ➜ string input; defaults to system drive
- $BitLockerProtection ➜ dropdown; state
- $RecoveryKeyAction ➜ dropdown; handle recovery key
- $BitlockerEncryptionMethod ➜ dropdown; only applicable when enabling from a complete off state
- $UseTpmProtector ➜ checkbox; use TPM with BitLocker
- $BackupToAD ➜ checkbox; store recovery key in AD device object
- $UseUsedSpaceOnly ➜ checkbox; only applicable when enabling from a complete off state
- $AutoReboot ➜ AutoReboot the device after execution
- $SaveLogToDevice ➜ checkbox; save a local log. See details in script

### === Other Management Options ⤴ ===
#### Static Options
- $PreventKeyPromptOnEveryBoot ➜ **SEE SCRIPT FOR NOTES**
- $SuspensionRebootCount ➜ Set how many reboots to apply bitlocker suspension

### === Status Scripts Options ===
#### RMM Input Options
- $UpdateRecoveryKey ➜ checkbox; optionally store the recovery key when run (if applicable)
- $MountPoint ➜ Hard set via variable fallback to System Drive
- $SaveLogToDevice ➜ checkbox; save a local log. See details in script

### === Custom Secure Fields ===
#### Standard Fields (Non-WYSIWYG)
- $MountPointFieldName
- $ProtectionStateFieldName
- $EncryptionMethodFieldName
- $UsedSpaceOnlyFieldName
- $CurrentProtectorsFieldName
- $RecoveryKeySecureFieldName (secure)

#### WYSIWYG Fields
- BitLockerStatusFieldName
- $RecoveryKeySecureFieldName (secure)

### === Card Customization (WYSIWYG) ===
#### Located near top of WYSIWYG scripts
- $CardTitle
- $CardIcon
- $CardBackgroundGradient
- $CardBorderRadius

---

## Script Details

### === Bitlocker Management WYSIWYG ===
**Manage & store** the Bitlocker status in a single custom field (WYSIWYG).
It will be formatted in the NinjaRMM Device Custom Fields tab.
An image may be seen below.

### === Bitlocker Management ===
This operates under the same logic as the WYSIWYG script.
The difference being, it stores each state in its own custom field.
Less complexity, much easier to adapt for your own use.

### === Bitlocker Status WYSIWYG ===
**Only stores** the Bitlocker status in a single custom field (WYSIWYG).
Unlike the management scripts, this will only update the current bitlocker information (not manage it).
It is useful to retrive bitlocker information, or run on a schedule to maintain BitLocker information in your environment.

### === Bitlocker Status ===
This operates under the same logic as the WYSIWYG script.
The difference being, it stores each state in its own custom field.
Less complexity, much easier to adapt for your own use.

<img src="https://raw.githubusercontent.com/SunshineSam/Scripting/main/NinjaRMM/Bitlocker/images/CardIconEnabled.png" alt="BitLocker Enabled Icon" width="360px" />

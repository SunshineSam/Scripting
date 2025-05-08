# All Things Bitlocker

### === Bitlocker Management ===
####   Static Custom Fields
- $RecoveryKeySecureFieldName = "BitLockerRecoveryKey" (secure)
- $MountPointFieldName = "BitLockerMountPoint"
- $ProtectionStateFieldName = "BitLockerProtectionState"
- $EncryptionMethodFieldName = "BitLockerEncryptionMethod"
- $UsedSpaceOnlyFieldName = "BitLockerUsedSpaceOnly"
- $CurrentProtectorsFieldName = "BitLockerCurrentProtectors"
#### Modify the string literal/ value for each FieldName variable

---

### === Bitlocker Status ===
#### Dynamic Custom Fields
- $MountPointFieldName
- $ProtectionStateFieldName
- $EncryptionMethodFieldName
- $CurrentProtectorsFieldName
- $RecoveryKeySecureFieldName (secure)
#### RMM Variables are resolved via env: input from the automation UI
#### Be sure to set the proper string input names for your custom fields

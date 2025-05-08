#Requires -Version 5.1

<#
.SYNOPSIS
    Manage BitLocker end-to-end with dropdown selections for mutually exclusive actions.
    
.DESCRIPTION
    • Auto-detect OS drive or use provided mount point  
    • Dropdowns (ValidateSet) ensure only one protection, one suspension, and one recovery action can be chosen  
    • Fallback to env: variables if RMM variable resolution fails 
    • Validate and Sanitize input
    • Sectional logging and sublogic comments for each block
    • Ensures recovery key and TPM are always present unless $PreventKeyPromptOnEveryBoot is false
    • Stores recovery key in NinjaRMM secure field 'BitLockerRecoveryKey' at the end of the script
    
.PARAMETER MountPoint
    Target drive letter or mount point (env: bitlockerMountPoint or system drive)
.PARAMETER BitLockerProtection
    Dropdown: Enable, Suspend, or Disable protection (required)
.PARAMETER RecoveryKeyAction
    Dropdown: Ensure, Rotate, or Remove numeric recovery key (required)
.PARAMETER BitlockerEncryptionMethod
    Dropdown: Aes128, Aes256, XtsAes128, or XtsAes256 BitLocker encryption method (required)
.PARAMETER BackupToAD
    Switch to backup recovery keys to AD
.PARAMETER AutoReboot
    Switch to reboot after Enable or Suspend
.PARAMETER SuspensionRebootCount
    Number of reboots to allow for suspended protection (default 1)
.PARAMETER UseUsedSpaceOnly
    Set encryption for used space only. This will cause bitlocker to work much harder to maintain encryption.
.PARAMETER SaveLogToDevice
    Optionally save the log to the device. C:\Logs\BitLockerScript.log
#>

[CmdletBinding()]
param(
    # Drive letter or mount point
    [string]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint } else { (Get-CimInstance Win32_OperatingSystem).SystemDrive }),
    
    # choose exactly one of these
    [ValidateSet("Enable","Suspend","Disable")][string]$BitLockerProtection,
    [ValidateSet("Ensure","Rotate","Remove")][string]$RecoveryKeyAction,
    [ValidateSet("Aes128", "Aes256", "XtsAes128", "XtsAes256")][string]$BitlockerEncryptionMethod,
    
    # remaining independent switches
    [switch]$UseTpmProtector = [Convert]::ToBoolean($env:useBitlockerTpmProtector),
    [switch]$BackupToAD  = [Convert]::ToBoolean($env:bitlockerBackupToAd),
    [switch]$AutoReboot  = [Convert]::ToBoolean($env:bitlockerAutoReboot),
    [switch]$SaveLogToDevice = [Convert]::ToBoolean($env:saveLogToDevice),
    [switch]$UseUsedSpaceOnly = [Convert]::ToBoolean($env:encryptUsedspaceonly),
    [int]$SuspensionRebootCount = $(if ($env:bitlockerSuspensionRebootCount) { [int]$env:bitlockerSuspensionRebootCount } else { 1 }),
    [int]$RebootDelay = 300
)

##########################################
# BEGIN: Initialization & Dropdown Fallback
##########################################
begin {
    
    ###########################################
    # Custom Feilds: Store BitLocker Management Information
    ##########################################
    
    # Static secure field name for storing recovery key
    $RecoveryKeySecureFieldName = "BitLockerRecoveryKey"
    
    # Static custom feild names for storing info
    $MountPointFieldName = "BitLockerMountPoint"
    $ProtectionStateFieldName = "BitLockerProtectionState"
    $EncryptionMethodFieldName = "BitLockerEncryptionMethod"
    $UsedSpaceOnlyFieldName = "BitLockerUsedSpaceOnly"
    $CurrentProtectorsFieldName = "BitLockerCurrentProtectors"
    
    # Hard set variable to ensure both TPM and Recovery Key protectors are always present when true
    $PreventKeyPromptOnEveryBoot = $true  # Set to $false to allow BitLocker without TPM; Will prompt for recovery key every boot
    
    # Immediate check if running >= administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Administrator privileges required"
        exit 1
    }
    Write-Host "Running as Administrator"
    
    Write-Host "`n=== Initialization & Validation ==="

    #####################################
    # Required Fields: Fallback to environment variables if RMM can't resolve...
    ####################################
    
    # Fallback to environment variables if Ninja can't resolve. 
    if (-not $BitLockerProtection -and $env:bitlockerProtection) {
        if ($env:bitlockerProtection -in @("Enable", "Suspend", "Disable")) {
            $BitLockerProtection = $env:bitlockerProtection
        }
        else {
            Write-Host "[ERROR] Environment variable bitlockerProtection '$env:bitlockerProtection' is invalid"
            exit 1
        }
    }
    if (-not $RecoveryKeyAction -and $env:bitlockerRecoveryKeyAction) {
        if ($env:bitlockerRecoveryKeyAction -in @("Ensure", "Rotate", "Remove")) {
            $RecoveryKeyAction = $env:bitlockerRecoveryKeyAction
        }
        else {
            Write-Host "[ERROR] Environment variable bitlockerRecoveryKeyAction '$env:bitlockerRecoveryKeyAction' is invalid"
            exit 1
        }
    }
    if (-not $BitlockerEncryptionMethod -and $env:bitlockerEncryptionMethod) {
        if ($env:bitlockerEncryptionMethod -in @("Aes128", "Aes256", "XtsAes128", "XtsAes256")) {
            $BitlockerEncryptionMethod = $env:bitlockerEncryptionMethod
        }
        else {
            Write-Host "[ERROR] Environment variable bitlockerEncryptionMethod '$env:bitlockerEncryptionMethod' is invalid"
            exit 1
        }
    }
    
    # Validate that mandatory parameters are set
    foreach ($paramName in @('BitLockerProtection', 'RecoveryKeyAction', 'BitlockerEncryptionMethod')) {
        if (-not (Get-Variable $paramName -ValueOnly)) {
            Write-Host "[ERROR] Missing required dropdown: $paramName"
            exit 1
        }
    }
    
    # If protection is set to "Disable", clear conflicting actions
    if ($BitLockerProtection -eq 'Disable') {
        Write-Host "[INFO] Protection = 'Disable'; clearing recovery, backup, and auto-reboot settings"
        $BackupToAD          = $false       # disable AD backup
        $AutoReboot          = $false       # disable automatic reboot
        Write-Host "[SUCCESS] All other operations disabled because protection is set to Disable"
    }
    
    # Validate MountPoint
    if (-not $MountPoint) {
        Write-Host "[ERROR] MountPoint cannot be null"
        exit 1
    }
    $MountPoint = $MountPoint.Trim()
    if ($MountPoint -notmatch '^[A-Za-z]:\\?$') {
        Write-Host "[ERROR] MountPoint '$MountPoint' must be a valid drive letter (e.g., 'C:' or 'C:\\')"
        exit 1
    }
    if (-not (Test-Path $MountPoint -PathType Container)) {
        Write-Host "[ERROR] MountPoint '$MountPoint' does not exist or is not a valid volume"
        exit 1
    }
    
    # Validate SuspensionRebootCount
    if ($SuspensionRebootCount -lt 0) {
        Write-Host "[ERROR] SuspensionRebootCount must be a non-negative integer"
        exit 1
    }
    if ($SuspensionRebootCount -gt 10) {
        Write-Host "[WARNING] SuspensionRebootCount exceeds reasonable limit (10); setting to 10"
        $SuspensionRebootCount = 10
    }
    
    # Validate RebootDelay
    if ($RebootDelay -lt 0) {
        Write-Host "[ERROR] RebootDelay must be a non-negative integer"
        exit 1
    }
    if ($RebootDelay -gt 31536000) {
        Write-Host "[ERROR] RebootDelay exceeds maximum allowed value (31536000 seconds)"
        exit 1
    }
    
    # Default encryption method if still unset
    if (-not $BitlockerEncryptionMethod) {
        Write-Host "[WARNING] BitlockerEncryptionMethod not set; defaulting to 'XtsAes256'"
        $BitlockerEncryptionMethod = "XtsAes256"
    }
    
    Write-Host "[SUCCESS] Dropdown values loaded:"
    Write-Host "  - BitLocker Mount Point: $MountPoint"
    Write-Host "  - Protection: $BitLockerProtection"
    Write-Host "  - Recovery Key: $RecoveryKeyAction"
    Write-Host "  - Encryption Method: $BitlockerEncryptionMethod"
    Write-Host "  - Use TPM: $UseTpmProtector"
    Write-Host "  - Backup to AD: $BackupToAD"
    Write-Host "  - Prevent Key Prompt On Every Boot: $PreventKeyPromptOnEveryBoot"
    
    # Sanitization Section: Correct impossible or conflicting input combinations with detailed output
    Write-Host "`n=== Section: Sanitization ==="
    
    # PreventKeyPromptOnEveryBoot sanitization
    if ($PreventKeyPromptOnEveryBoot) {
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is ON; checking TPM and Recovery Key requirements"
        if ($BitLockerProtection -in @("Enable", "Suspend")) {
            Write-Host "[INFO] Protection action '$BitLockerProtection' selected; validating protector requirements"
            # Sublogic: if TPM is disabled and Bitlocker is Enabled/Suspeneded, handle based on PreventKeyPromptOnEveryBoot bool
            if (-not $UseTpmProtector) {
                Write-Host "[WARNING] TPM protector enforcement: UseTpmProtector was false, but PreventKeyPromptOnEveryBoot requires TPM for '$BitLockerProtection'. Setting UseTpmProtector to true."
                $UseTpmProtector = $true
            }
            else {
                Write-Host "[SUCCESS] TPM protector enforcement: UseTpmProtector is true, meeting PreventKeyPromptOnEveryBoot requirement"
            }
            # Sublogic: If recovery key was set to remove and Bitlocker is Enabled/Suspeneded, set to Ensure. There will ALWAYS be a BitLocker recovery key when enabled/suspened
            if ($RecoveryKeyAction -eq "Remove") {
                Write-Host "[WARNING] Recovery Key enforcement: RecoveryKeyAction was 'Remove', but PreventKeyPromptOnEveryBoot requires a recovery key for '$BitLockerProtection'. Setting RecoveryKeyAction to 'Ensure'."
                $RecoveryKeyAction = "Ensure"
            }
            else {
                Write-Host "[SUCCESS] Recovery Key enforcement: RecoveryKeyAction is '$RecoveryKeyAction', meeting PreventKeyPromptOnEveryBoot requirement"
            }
        }
        else {
            Write-Host "[INFO] Protection action '$BitLockerProtection' selected; no additional TPM or Recovery Key enforcement needed"
        }
    }
    # Sublogic: PreventKeyPromptOnEveryBoot handling when not enabled/true - proper sanitization and handling of states
    else {
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is false; skipping strict TPM and Recovery Key enforcement checks.`nThis may result in BitLocker prompting during EVERY BOOT if you remove the TPM."
        if (-not $UseTpmProtector -and $BitLockerProtection -in @("Enable", "Suspend")) {
            Write-Host "[INFO] UseTpmProtector is false for '$BitLockerProtection'; checking Recovery Key requirement"
            # Sublogic: Always ensure RecoveryKeyAction is ensured when Bitlocker is enabled/suspened, regardless of PreventKeyPromptOnEveryBoot state. This ensure recovery key management all of the time
            if ($RecoveryKeyAction -eq "Remove") {
                Write-Host "[WARNING] RecoveryKeyAction was 'Remove', but a recovery key is required without TPM for '$BitLockerProtection'. Setting RecoveryKeyAction to 'Ensure'."
                $RecoveryKeyAction = "Ensure"
            }
            else {
                Write-Host "[SUCCESS] RecoveryKeyAction is '$RecoveryKeyAction', meeting requirement without TPM"
            }
        }
    }
    
    # BitLocker Protection Status sanitization
    if ($BitLockerProtection -eq "Disable") {
        Write-Host "[INFO] Protection action 'Disable' selected; validating possible conflicting settings"
        if ($RecoveryKeyAction -in @("Ensure", "Rotate")) {
            Write-Host "[WARNING] RecoveryKeyAction was '$RecoveryKeyAction', but 'Disable' only allows 'Remove'. Setting RecoveryKeyAction to 'Remove'."
            $RecoveryKeyAction = "Remove"
        }
        else {
            Write-Host "[SUCCESS] RecoveryKeyAction is '$RecoveryKeyAction', compatible with 'Disable'"
        }
    }
    
    # Ensure AutoReboot aligns with Enable or Suspend
    if ($AutoReboot -and $BitLockerProtection -notin @("Enable", "Suspend")) {
        Write-Host "[WARNING] AutoReboot is true but incompatible with '$BitLockerProtection'; setting to false"
        $AutoReboot = $false
    }
    
    Write-Host "[SUCCESS] Input sanitization completed successfully"
    
    #######################
    # Helper Functions
    #######################

    # Helper function: universal call for Write-Log
    function Write-Log {
        param (
            [string]$Level,
            [string]$Message
        )
        # Sublogic: Output the log message to the console
        Write-Host "[$Level] $Message"
        
        # Sublogic: Save the log message to a file on the device if enabled
        if ($SaveLogToDevice) {
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $logMessage = "[$timestamp] [$Level] $Message"
            
            $driveLetter = ($MountPoint -replace '[^A-Za-z]', '').ToUpper()
            $logDir = "$driveLetter`:\Logs"
            $logFile = Join-Path $logDir "BitLockerScript.log"
            
            # Sublogic: Create the log directory if it doesn’t exist
            if (-not (Test-Path $logDir)) {
                try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {}
            }
            
            # Sublogic: Add a daily header to the log file if not already present
            $today = Get-Date -Format 'yyyy-MM-dd'
            $header = "=== $today ==="
            $existingContent = if (Test-Path $logFile) { Get-Content $logFile -Raw } else { "" }
            if (-not $existingContent -or -not ($existingContent -match [regex]::Escape($header))) {
                Add-Content -Path $logFile -Value "`r`n$header"
            }
            
            Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
        }
    }
    
    # Helper function: refresh drive state; string
    function Get-VolumeObject {
        try {
            # Sublogic: Retrieve BitLocker volume object and suppress all non-error output
            $global:blv = Get-BitLockerVolume `
                -MountPoint $MountPoint `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue
            # Only log volume state if not already logged for this mount point in this run
            if (-not $script:LastLogContext) { $script:LastLogContext = @{} }
            if (-not $script:LastLogContext.ContainsKey("VolumeState-$MountPoint")) {
                Write-Log "SUCCESS" "Volume state refreshed: ProtectionStatus=$($blv.ProtectionStatus), VolumeStatus=$($blv.VolumeStatus)"
                $script:LastLogContext["VolumeState-$MountPoint"] = $true
            }
        }
        catch {
            Write-Log "ERROR" "No BitLocker volume at ${MountPoint}: $_"
            exit 1
        }
    }

    # Helper function: detect if BitLocker is awaiting key backup before activation. Usually occurs during first ever activation.
    function Test-IsKeyBackupRequired {
        param($volume)
        # Sublogic: Suppress logging from nested recovery protector scans
        $script:SuppressRecoveryProtectorScanLog = $true
        $valid = Get-ValidRecoveryProtectors -v $volume
        $script:SuppressRecoveryProtectorScanLog = $false
        
        # Sublogic: Check if volume is fully encrypted with protection off and a recovery protector exists
        if ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 0 -and $valid.Count -gt 0) {
            if (-not $script:LastLogContext) { $script:LastLogContext = @{} }
            if (-not $BackupToAD -and -not $script:LastLogContext.ContainsKey("KeyBackupRequired-$($volume.MountPoint)")) {
                Write-Log "INFO" "BitLocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and or resuming protection."
                $script:LastLogContext["KeyBackupRequired-$($volume.MountPoint)"] = $true
            }
            return $true
        }
        return $false
    }
    
    # Helper function: return the list of valid protectors; list
    function Get-ValidRecoveryProtectors {
        param($volume)
        # Only log the scan message if this is the top-level call, not if called internally by Test-RecoveryPasswordPresent etc
        if (-not $script:SuppressRecoveryProtectorScanLog) {
            Write-Log "INFO" "Scanning for valid RecoveryPassword protectors..."
        }
        # Sublogic: Check if KeyProtector array exists on the volume
        if (-not $volume.KeyProtector) {
            Write-Log "WARNING" "No KeyProtector array found on volume"
            return @()
        }
        # Sublogic: Filter for RecoveryPassword protectors
        $candidates = $volume.KeyProtector | Where-Object {
            $_.KeyProtectorType -ieq 'RecoveryPassword'
        }
        if (-not $candidates) {
            Write-Log "INFO" "No RecoveryPassword entries found"
            return @()
        }
        $valid = @()
        # Sublogic: Validate each recovery protector’s ID format
        foreach ($keypair in $candidates) {
            if ($keypair.KeyProtectorId -match '^\{[0-9a-f\-]+\}$') {
                if (-not $script:LoggedRecoveryFound) { $script:LoggedRecoveryFound = @{} }
                if (-not $script:LoggedRecoveryFound.ContainsKey($volume.MountPoint)) {
                    Write-Log "INFO" "Found valid recovery key protector"
                    $script:LoggedRecoveryFound[$volume.MountPoint] = $true
                }
                $valid += $keypair
            } else {
                Write-Log "WARNING" "Ignoring invalid protector ID: $($keypair.KeyProtectorId)"
            }
        }
        if (-not $valid) {
            Write-Log "WARNING" "No valid RecoveryPassword protectors found"
        }
        return $valid
    }
    
    # Helper function: if there is an existing recovery password; bool
    function Test-RecoveryPasswordPresent {
        param($volume, [switch]$SuppressLog)
        # Sublogic: Suppress nested recovery protector scan logs
        $script:SuppressRecoveryProtectorScanLog = $true
        $valid = Get-ValidRecoveryProtectors -v $volume
        $script:SuppressRecoveryProtectorScanLog = $false
        
        # Sublogic: Determine if a valid recovery password protector exists and log relevant status
        if ($valid.Count -gt 0) {
            if (-not $SuppressLog -and -not $script:LastLogContext.ContainsKey("RecoveryPresent-$($volume.MountPoint)")) {
                if ($volume.VolumeStatus -eq 'EncryptionInProgress' -or $volume.VolumeStatus -eq 'EncryptionPaused') {
                    Write-Log "INFO" "BitLocker is encrypting (status: $($volume.VolumeStatus))."
                }
                elseif ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 0) {
                    Write-Log "INFO" "BitLocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and or resuming protection."
                }
                elseif ($volume.ProtectionStatus -eq 'Off') {
                    if ($volume.VolumeStatus -eq 'DecryptionInProgress') {
                        Write-Log "INFO" "BitLocker is decrypting the volume. Please wait until decryption is complete before restarting."
                    }
                    else {
                        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
                        if ($hasTpm) {
                            Write-Log "INFO" "BitLocker is Off with a TPM protector. Resume protection or reboot to finalize."
                        }
                    }
                }
                $script:LastLogContext["RecoveryPresent-$($volume.MountPoint)"] = $true
            }
            return $true
        }
        else {
            if (-not $SuppressLog -and -not $script:LastLogContext.ContainsKey("NoRecoveryPresent-$($volume.MountPoint)")) {
                Write-Log "INFO" "No valid numeric recovery protector found."
                $script:LastLogContext["NoRecoveryPresent-$($volume.MountPoint)"] = $true
            }
            return $false
        }
    }
    
    # Helper function: ensure recovery key exists
    function Ensure-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Adding numeric recovery protector"
        try {
            $result = Add-BitLockerKeyProtector `
                -MountPoint $volume.MountPoint `
                -RecoveryPasswordProtector `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue
            $script:NumericProtectorCreated = $true
            Write-Log "SUCCESS" "Numeric recovery protector added"
        }
        catch {
            Write-Log "ERROR" "Failed to add numeric protector: $_"
        }
    }
    
    # Helper function: rotate recovery key
    function Rotate-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Rotating numeric recovery protector"
        # Sublogic: Remove existing numeric protectors
        Write-Log "INFO" "Removing existing numeric protectors before rotation..."
        $existing = Get-ValidRecoveryProtectors -v $volume
        if (-not $existing) {
            Write-Log "WARNING" "No protectors to rotate; adding a new one"
        }
        else {
            foreach ($keypair in $existing) {
                try {
                    Remove-BitLockerKeyProtector `
                      -MountPoint $volume.MountPoint `
                      -KeyProtectorId $keypair.KeyProtectorId `
                      -ErrorAction Stop `
                      -InformationAction SilentlyContinue | Out-Null
                    Write-Log "SUCCESS" "Removed protector $($keypair.KeyProtectorId)"
                }
                catch {
                    Write-Log "ERROR" "Failed to remove old protector $($keypair.KeyProtectorId): $_"
                }
            }
        }
        # Sublogic: Add a new recovery protector
        try {
            Add-BitLockerKeyProtector `
              -MountPoint $volume.MountPoint `
              -RecoveryPasswordProtector `
              -ErrorAction Stop `
              -WarningAction SilentlyContinue `
              -InformationAction SilentlyContinue | Out-Null
            $script:NumericProtectorCreated = $true
            Write-Log "SUCCESS" "Numeric recovery protector rotated"
        }
        catch {
            Write-Log "ERROR" "Failed to add new protector: $_"
        }
    }
    
    # Helper function: remove recovery key
    function Remove-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Removing numeric recovery protector(s)"
        
        $existing = Get-ValidRecoveryProtectors -v $volume
        
        # Sublogic: Check if there are any valid recovery protectors to remove
        if (-not $existing -or $existing.Count -eq 0) {
            Write-Log "WARNING" "No valid numeric protectors found; skipping removal"
            return
        }
        
        # Sublogic: Remove each valid recovery protector
        foreach ($keypair in $existing) {
            try {
                Remove-BitLockerKeyProtector `
                  -MountPoint $volume.MountPoint `
                  -KeyProtectorId $keypair.KeyProtectorId `
                  -ErrorAction Stop `
                  -InformationAction SilentlyContinue | Out-Null
                Write-Log "SUCCESS" "Removed protector $($keypair.KeyProtectorId)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $_"
            }
        }
        
        # Sublogic: Verify all protectors were removed
        $remaining = Get-ValidRecoveryProtectors -v $volume
        if ($remaining.Count -eq 0) {
            Write-Log "SUCCESS" "All valid numeric protectors removed"
        }
        else {
            Write-Log "WARNING" "Some protectors may not have been removed"
        }
    }

    # Helper function: remove all existing protectors
    function Remove-AllProtectors {
        param($volume)
        Write-Log "INFO" "Removing all existing key protectors"
        $protectors = $volume.KeyProtector
        if (-not $protectors) {
            Write-Log "INFO" "No protectors found to remove"
            return
        }
        foreach ($keypair in $protectors) {
            try {
                Remove-BitLockerKeyProtector `
                    -MountPoint $volume.MountPoint `
                    -KeyProtectorId $keypair.KeyProtectorId `
                    -ErrorAction Stop `
                    -InformationAction SilentlyContinue | Out-Null
                Write-Log "SUCCESS" "Removed protector $($keypair.KeyProtectorId)"
            }
            catch {
                Write-Log "ERROR" "Failed to remove protector $($keypair.KeyProtectorId): $_"
            }
        }
        Write-Log "SUCCESS" "All protectors removed"
    }

    # Helper function: manage the BitLocker Recovery Key Action selection (See above 3 functions being called)
    function Invoke-RecoveryAction {
        param(
            [Parameter(Mandatory)]$volume,
            [Parameter(Mandatory)][ValidateSet('Ensure','Rotate','Remove')]$Action,
            [Parameter()][switch]$SuppressLog
        )
        $recoveryPresent = Test-RecoveryPasswordPresent -v $volume -SuppressLog:$SuppressLog
        switch ($Action) {
            'Ensure' {
                if ($script:NumericProtectorCreated) {
                    if (-not $SuppressLog) { Write-Log "INFO" "Protector was just created; skipping Ensure" }
                }
                elseif ($recoveryPresent) {
                    if (-not $SuppressLog) { Write-Log "WARNING" "Valid recovery key already present; skipping Ensure" }
                }
                else {
                    Ensure-RecoveryKey -v $volume
                }
            }
            'Rotate' {
                if ($volume.VolumeStatus -ne 'FullyDecrypted') {
                    Rotate-RecoveryKey -v $volume
                }
                else {
                    if (-not $SuppressLog) { Write-Log "ERROR" "Volume is decrypted; cannot Rotate; skipping" }
                }
            }
            'Remove' {
                if ($PreventKeyPromptOnEveryBoot) {
                    Write-Log "WARNING" "Removal of recovery key is disabled when PreventKeyPromptOnEveryBoot is true; skipping"
                }
                elseif ($volume.ProtectionStatus -ne 'Off' -or $volume.VolumeStatus -ne 'FullyDecrypted') {
                    if (-not $SuppressLog) { Write-Log "WARNING" "Cannot remove recovery key when BitLocker is enabled or suspended; skipping" }
                }
                elseif (-not $recoveryPresent) {
                    if (-not $SuppressLog) { Write-Log "WARNING" "No valid recovery key to Remove; skipping" }
                }
                else {
                    Remove-RecoveryKey -v $volume
                }
            }
        }
    }
    
    # Helper function: save key to Active Directory
    function Backup-KeyToAD {
        param($volume)
        Write-Log "INFO" "Preparing to back up numeric recovery protector(s) to AD"
        
        # Sublogic: Check if the computer is domain-joined
        $cs = Get-CimInstance Win32_ComputerSystem
        if (-not $cs.PartOfDomain) {
            Write-Log "WARNING" "Computer is not domain-joined; skipping AD backup"
            return
        }
        
        $protectors = Get-ValidRecoveryProtectors -v $volume
        Write-Log "INFO" "Found $($protectors.Count) valid protector(s) to back up to AD"
        if (-not $protectors) {
            Write-Log "WARNING" "No numeric recovery protectors found; nothing to back up"
            return
        }
        
        # Sublogic: Backup each valid recovery protector to AD
        foreach ($keypair in $protectors) {
            Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AD"
            try {
                Backup-BitLockerKeyProtector `
                  -MountPoint $volume.MountPoint `
                  -KeyProtectorId $keypair.KeyProtectorId `
                  -ErrorAction Stop `
                  -InformationAction SilentlyContinue | Out-Null
                Write-Log "SUCCESS" "Protector ID $($keypair.KeyProtectorId) backed up"
            }
            catch {
                Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId): $_"
            }
        }
    }
    
    # Helper function: Check TPM pending status
    function Test-TpmPending {
        param($volume)
        # Sublogic: Determine if a TPM protector is pending based on protection status and presence
        $isOff = ($volume.ProtectionStatus -eq 0)
        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
        if ($isOff -and $hasTpm -and (Test-IsKeyBackupRequired -v $volume)) {
            return $false
        }
        return ($isOff -and $hasTpm)
    }
    
    # Helper function: validate TPM exists 
    function Ensure-TpmProtector {
        param($volume)
        Write-Log "INFO" "Ensuring TPM protector exists"
        # Sublogic: Verify TPM availability
        try {
            $tpm = Get-Tpm
            if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) {
                Write-Log "WARNING" "TPM is not available or not ready; skipping TPM protector addition"
                return
            }
        } catch {
            Write-Log "WARNING" "Failed to check TPM status: $_; skipping TPM protector addition"
            return
        }
        # Sublogic: Check if TPM protector already exists
        if ($volume.KeyProtector | Where-Object KeyProtectorType -eq 'Tpm') {
            Write-Log "SUCCESS" "TPM protector already present"
            return
        }
        # Sublogic: Add a TPM protector
        try {
            Add-BitLockerKeyProtector `
              -MountPoint $volume.MountPoint `
              -TpmProtector `
              -ErrorAction Stop `
              -WarningAction SilentlyContinue `
              -InformationAction SilentlyContinue | Out-Null
            Write-Log "SUCCESS" "TPM protector added (pending reboot)"
            if ($script:initialProtectionStatus -eq 'Off') {
                Write-Log "INFO" "Requires TPM during enablement (from a complete off state). You may remove later."
            }
        }
        catch {
            Write-Log "ERROR" "Failed to add TPM protector: $_"
        }
    }
    
    # Helper function: check if TPM is pending a restart or encryption already in progress
    function Check-RestartRequirement {
        param($volume)
        # Sublogic: Check if volume is fully decrypted and protectors are present
        if ($volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
            $hasRecovery = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
            if ($hasTpm -and $hasRecovery) {
                return "BitLocker enabled with TPM and recovery key protectors. No restart required."
            }
            elseif ($hasTpm) {
                return "Restart required to complete BitLocker setup with TPM."
            }
        }
        elseif ($volume.ProtectionStatus -eq 'On' -and $volume.VolumeStatus -eq 'EncryptionInProgress') {
            return "Restart may be beneficial to speed up encryption process."
        }
        return $null
    }
    
    # Helper function: Log recovery key
    function Log-RecoveryKey {
        param($volume)
        $protectors = Get-ValidRecoveryProtectors -v $volume
        if ($protectors) {
            # Safe - Function only called for saftey when BitLocker is disabled, and in any possible case may present a recovery key still (in the possibly unlikely case, will be in RMM log, and stored on device if selected)
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Recovery Key ID: $($keypair.KeyProtectorId), Key: $($keypair.RecoveryPassword)"
            }
        }
    }

    # Helper function: Output protectors (see above function called)
    function Log-Protectors {
        param($volume)
        # Sublogic: Log the count and types of current protectors
        $protectors = $volume.KeyProtector
        $count = $protectors.Count
        Write-Log "INFO" "Current protectors: $count"
        $types = $protectors | ForEach-Object { $_.KeyProtectorType }
        Write-Log "INFO" "  - Types: $($types -join ', ')"
        # Sublogic: Log recovery key only if protection is off and volume is fully decrypted
        if ($volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Log-RecoveryKey -v $volume
        }
    }
    
    # Helper function: Validate TPM state and system configuration
    function Validate-BitLockerState {
        param($volume)
        # Sublogic: Check for pending reboots
        $rebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if ($rebootPending) {
            Write-Log "WARNING" "A system reboot is pending, which may affect BitLocker configuration. A reboot is recommended after changes have been made."
        }
        
        # Sublogic: Check TPM status
        try {
            $tpm = Get-Tpm
            if ($tpm.TpmPresent -and !$tpm.TpmReady) {
                Write-Log "WARNING" "TPM is present but not ready. This may cause BitLocker to enter recovery mode during the next boot."
            }
        }
        catch {
            Write-Log "WARNING" "Unable to check TPM status: $_"
        }
        
        # Sublogic: Check for Group Policy settings that may enforce TPM
        $gpoPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        if (Test-Path $gpoPath) {
            $useTpm = Get-ItemProperty -Path $gpoPath -Name "UseTPM" -ErrorAction SilentlyContinue
            if ($useTpm -and $useTpm.UseTPM -eq 1 -and !$UseTpmProtector) {
                Write-Log "WARNING" "Group Policy requires TPM protector, but UseTpmProtector is False. This may cause recovery prompt."
            }
        }
        
        # Sublogic: Check protector configuration
        $protectors = $volume.KeyProtector
        if ($protectors.Count -eq 0) {
            Write-Log "WARNING" "No protectors configured for volume. BitLocker will not function until protectors are added."
        }
    }

    # Helper function: Store current protectors in NinjaRMM custom field
    function Store-CurrentProtectors {
        param($volume)
        Write-Log "INFO" "Attempting to store current protectors in custom field"
        try {
            if ($volume.KeyProtector) {
                $protectorTypes = $volume.KeyProtector | ForEach-Object { $_.KeyProtectorType }
                $protectorsString = $protectorTypes -join "`n"
            }
            else {
                $protectorsString = "None"
            }
            Ninja-Property-Set $CurrentProtectorsFieldName $protectorsString | Out-Null
            Write-Log "SUCCESS" "Current protectors stored in custom field '$CurrentProtectorsFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store current protectors: $_"
        }
    }

    # Helper function: store recovery key, set secure feild to empty if bitlocker is already fully disabled 
    function Store-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Attempting to store current recovery key in secure field"
        
        # Check if there are no protectors and the volume is fully disabled
        if (-not $volume.KeyProtector -and $volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "INFO" "No protectors and volume is fully disabled; setting recovery key to 'N/A'"
            try {
                Ninja-Property-Set $RecoveryKeySecureFieldName "N/A" | Out-Null
                Write-Log "SUCCESS" "Recovery key set to 'N/A' in secure field '$RecoveryKeySecureFieldName'"
            }
            catch {
                Write-Log "ERROR" "Failed to set recovery key to 'N/A': $_"
            }
            return
        }
        
        $maxRetries = 5
        $retryDelay = 2
        $retryCount = 0
        $protectors = $null
        
        # Retry loop to detect the new key
        do {
            Get-VolumeObject  # Refresh volume object each attempt
            $protectors = Get-ValidRecoveryProtectors -v $volume
            if ($protectors) {
                $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
                if ($RecoveryKeyAction -eq 'Rotate' -and $script:PreviousRecoveryKey -and $latestProtector.KeyProtectorId -eq $script:PreviousRecoveryKey.KeyProtectorId) {
                    Write-Log "WARNING" "Detected old key ID $($latestProtector.KeyProtectorId) on attempt $($retryCount + 1); waiting for new key"
                }
                else {
                    Write-Log "INFO" "Detected new or current key ID $($latestProtector.KeyProtectorId) on attempt $($retryCount + 1)"
                    break
                }
            }
            else {
                Write-Log "WARNING" "No recovery key protectors detected on attempt $($retryCount + 1); retrying in $retryDelay seconds"
            }
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
        while ($retryCount -lt $maxRetries)
        
        # Store the latest key if available
        if ($protectors) {
            $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
            $keyInfo = "ID: $($latestProtector.KeyProtectorId)`nKey: $($latestProtector.RecoveryPassword)"
            Write-Log "INFO" "Storing recovery key: $($latestProtector.KeyProtectorId)"
            try {
                Ninja-Property-Set $RecoveryKeySecureFieldName $keyInfo | Out-Null
                Write-Log "SUCCESS" "Recovery key stored/updated in secure field '$RecoveryKeySecureFieldName'"
            }
            catch {
                Write-Log "ERROR" "Failed to store recovery key: $_"
            }
        }
        else {
            Write-Log "WARNING" "No recovery key protectors found after $maxRetries retries; secure field not updated"
        }
    }

    # Helper function: Store mount point in NinjaRMM custom field
    function Store-MountPoint {
        param($mountPoint)
        Write-Log "INFO" "Attempting to store mount point in custom field"
        try {
            Ninja-Property-Set $MountPointFieldName $mountPoint | Out-Null
            Write-Log "SUCCESS" "Mount point stored in custom field '$MountPointFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store mount point: $_"
        }
    }

    # Helper function: Store protection state in NinjaRMM custom field
    function Store-ProtectionState {
        param($protectionState)
        Write-Log "INFO" "Attempting to store protection state in custom field"
        try {
            Ninja-Property-Set $ProtectionStateFieldName $protectionState | Out-Null
            Write-Log "SUCCESS" "Protection state stored in custom field '$ProtectionStateFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store protection state: $_"
        }
    }

    # Helper function: Store encryption method in NinjaRMM custom field
    function Store-EncryptionMethod {
        param($encryptionMethod)
        Write-Log "INFO" "Attempting to store encryption method in custom field"
        try {
            Ninja-Property-Set $EncryptionMethodFieldName $encryptionMethod | Out-Null
            Write-Log "SUCCESS" "Encryption method stored in custom field '$EncryptionMethodFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store encryption method: $_"
        }
    }

    # Helper function: Store used space only flag in NinjaRMM custom field
    function Store-UsedSpaceOnly {
        param($usedSpaceOnly)
        Write-Log "INFO" "Attempting to store used space only flag in custom field"
        try {
            $valueToStore = if ($usedSpaceOnly -is [bool]) { $usedSpaceOnly.ToString() } else { $usedSpaceOnly }
            Ninja-Property-Set $UsedSpaceOnlyFieldName $valueToStore | Out-Null
            Write-Log "SUCCESS" "Used space only flag stored in custom field '$UsedSpaceOnlyFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store used space only flag: $_"
        }
    }

    # Helper function: parse the switch input for state management
    function Get-DesiredProtectionState {
        param($action)
        switch ($action) {
            'Enable'  { return 'Enabled' }
            'Suspend' { return 'Suspended' }
            'Disable' { return 'Disabled' }
            default   { return 'Unknown' }
        }
    }
}

#####################################
# PROCESS: Execute BitLocker Actions
#####################################
process {
    # State management variables
    $script:NumericProtectorCreated = $false
    $script:LastLogContext = @{}
    $script:LoggedRecoveryFound = @{}
    
    Write-Host "`n=== Section: Volume Detection ==="
    Write-Log "INFO" "Retrieving BitLocker volume for $MountPoint"

    # Update the 
    Get-VolumeObject

    # Track initial protection status from the Get-VolumeObject call
    $script:initialProtectionStatus = $blv.ProtectionStatus
    
    Write-Host "`n=== Section: Protection State Check ==="
    # Validate BitLocker and TPM state
    Validate-BitLockerState -v $blv
    
    # Evaluate TPM status and restart requirements
    $isTpmPending = $false
    if ($blv.ProtectionStatus -eq 'Off') {
        $isTpmPending = Test-TpmPending -v $blv
        if ($isTpmPending) {
            $restartMessage = Check-RestartRequirement -v $blv
            switch ($BitLockerProtection) {
                'Enable' {
                    Write-Log "INFO" "TPM is pending, but 'Enable' selected — continuing"
                    if ($restartMessage) {
                        Write-Log "INFO" $restartMessage
                    }
                }
                'Suspend' {
                    Write-Log "WARNING" "Cannot suspend — BitLocker is not yet enabled."
                    if ($restartMessage) {
                        Write-Log "INFO" $restartMessage
                    }
                    exit 0
                }
                default {
                    Write-Log "WARNING" "TPM protector added but protection is Off; restart may be required."
                    if ($restartMessage) {
                        Write-Log "INFO" $restartMessage
                    }
                    exit 0
                }
            }
        } else {
            Write-Log "INFO" "BitLocker is not enabled and no TPM protector is pending."
        }
    }
    elseif ($blv.ProtectionStatus -eq 2) {
        Write-Log "INFO" "BitLocker is in a suspended state."
    }
    
    Write-Host "`n=== Section: Protection (using: $BitLockerProtection) ==="

    # Manage the switch case logic for the BitLocker ptotection selection
    switch ($BitLockerProtection) {
        'Enable' {
            Write-Log "INFO" "Requested: Enable/Resume protection"
            if ($blv.ProtectionStatus -eq 2) {
                Write-Log "INFO" "BitLocker is suspended; resuming protection"
                if ($PreventKeyPromptOnEveryBoot) {
                    Ensure-TpmProtector -v $blv
                    # Respect user-specified RecoveryKeyAction (e.g., 'Rotate')
                    Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                    Get-VolumeObject  # Refresh volume object after recovery action
                }
                try {
                    Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                    Write-Log "SUCCESS" "Protection resumed"
                    Get-VolumeObject
                    $finalEnableState = "resumed"
                }
                catch {
                    Write-Log "ERROR" "Failed to resume protection: $_"
                    exit 1
                }
            }
            elseif ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                Write-Log "INFO" "Volume is FullyEncrypted but Protection is Off; adding protectors and resuming before recovery action"
                if ($PreventKeyPromptOnEveryBoot) {
                    Ensure-TpmProtector -v $blv
                    # Resume protection first to ensure rotation can proceed
                    try {
                        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                        Write-Log "SUCCESS" "Protection resumed before recovery action"
                        Get-VolumeObject  # Refresh volume object after resuming protection
                        # Set previous recovery key before rotation
                        $script:PreviousRecoveryKey = (Get-ValidRecoveryProtectors -v $blv | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1)
                        # Now perform the recovery key rotation
                        Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                        Get-VolumeObject  # Refresh volume object after rotation
                        $finalEnableState = "resumed"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to resume protection: $_"
                        exit 1
                    }
                }
                else {
                    if ($UseTpmProtector) {
                        Ensure-TpmProtector -v $blv
                    }
                    try {
                        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                        Write-Log "SUCCESS" "Protection resumed"
                        Get-VolumeObject
                        Invoke-RecoveryAction -v $blv -Action 'Ensure' -SuppressLog
                        $finalEnableState = "resumed"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to resume protection: $_"
                        exit 1
                    }
                }
            }
            elseif ($blv.ProtectionStatus -eq 'Off') {
                # Sublogic: Enable protection and apply protectors if off
                Write-Log "INFO" "Volume is off; enabling with protectors"
                if ($blv.VolumeStatus -eq 'DecryptionInProgress') {
                    Write-Log "WARNING" "Volume is decrypting; skipping enablement for safety"
                    exit 0
                }
                if ($blv.VolumeStatus -eq 'FullyDecrypted') {
                    Remove-AllProtectors -v $blv
                }
                # Log the encryption approach
                if ($UseUsedSpaceOnly) {
                    Write-Log "INFO" "Enabling BitLocker with -UsedSpaceOnly"
                }
                else {
                    Write-Log "INFO" "Enabling BitLocker without -UsedSpaceOnly (full disk encryption)"
                }
                
                # Enable BitLocker with RecoveryPasswordProtector
                Write-Log "INFO" "Enabling BitLocker with Recovery Password protector"
                try {
                    Enable-BitLocker `
                        -MountPoint $MountPoint `
                        -EncryptionMethod $BitlockerEncryptionMethod `
                        -RecoveryPasswordProtector `
                        -SkipHardwareTest `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue `
                        -InformationAction SilentlyContinue `
                        -UsedSpaceOnly:$UseUsedSpaceOnly | Out-Null
                    Write-Log "SUCCESS" "BitLocker enabled with recovery key protector"
                    Get-VolumeObject
                }
                catch {
                    Write-Log "ERROR" "Failed to enable BitLocker: $_"
                    exit 1
                }
            
                # Add TPM protector if required
                # Will always be true with PreventKeyPromptOnEveryBoot
                if ($UseTpmProtector) {
                    Write-Log "INFO" "Adding TPM protector post-enablement"
                    Ensure-TpmProtector -v $blv
                    Get-VolumeObject
                }
            
                $finalEnableState = "enabled"
            }
            else {
                # Protection already active; reconcile protectors and handle recovery key action
                Write-Log "INFO" "Protection already active; reconciling protectors"
                if ($PreventKeyPromptOnEveryBoot) {
                    Ensure-TpmProtector -v $blv
                    # Always ensure a recovery key, but allow rotation if requested
                    Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                }
                else {
                    Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                    if ($UseTpmProtector) {
                        Ensure-TpmProtector -v $blv
                    }
                }
                Get-VolumeObject
                if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted') {
                    Write-Log "INFO" "Protection is off after protector reconciliation; resuming protection"
                    try {
                        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
                        Write-Log "SUCCESS" "Protection resumed"
                        Get-VolumeObject
                    }
                    catch {
                        Write-Log "ERROR" "Failed to resume protection: $_"
                        exit 1
                    }
                }
                $finalEnableState = "reconciled"
            }
            
            if ($finalEnableState) {
                switch ($finalEnableState) {
                    'resumed' {
                        Write-Log "INFO" "BitLocker protection successfully resumed"
                    }
                    'enabled' {
                        if ($blv.VolumeStatus -eq 'EncryptionInProgress' -or $blv.VolumeStatus -eq 'EncryptionPaused') {
                            Write-Log "INFO" "BitLocker is encrypting (status: $($blv.VolumeStatus))."
                        }
                    }
                    'reconciled' {
                        Write-Log "INFO" "Protectors reconciled; protection status: $($blv.ProtectionStatus)"
                    }
                }
            }
        }
        'Suspend' {
            Write-Log "INFO" "Requested: Suspend protection"
            # Sublogic: Check if volume is encrypting
            if ($blv.VolumeStatus -eq 'EncryptionInProgress') {
                Write-Log "WARNING" "Cannot suspend — BitLocker is currently encrypting the volume."
            }
            elseif ($blv.ProtectionStatus -eq 2) {
                Write-Log "WARNING" "Already suspended; skipping"
            }
            else {
                # Sublogic: Ensure protectors before suspending if required
                if ($PreventKeyPromptOnEveryBoot) {
                    Ensure-TpmProtector -v $blv
                    Invoke-RecoveryAction -v $blv -Action 'Ensure' -SuppressLog
                }
                else {
                    if ($UseTpmProtector) {
                        Ensure-TpmProtector -v $blv
                    }
                    Invoke-RecoveryAction -v $blv -Action 'Ensure' -SuppressLog
                }
                Get-VolumeObject
                try {
                    Suspend-BitLocker -MountPoint $MountPoint -RebootCount $SuspensionRebootCount -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    Write-Log "SUCCESS" "Protection suspended for $SuspensionRebootCount reboot(s)"
                    Get-VolumeObject
                }
                catch {
                    Write-Log "ERROR" "Failed to suspend protection: $_"
                    exit 1
                }
            }
        }
        'Disable' {
            Write-Log "INFO" "Requested: Disable protection"
            # Sublogic: Disable protection if not already off
            if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
                Write-Log "WARNING" "Already disabled; skipping"
            }
            else {
                try {
                    Disable-BitLocker -MountPoint $MountPoint -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    Write-Log "SUCCESS" "Decryption initiated"
                    Get-VolumeObject
                }
                catch {
                    Write-Log "ERROR" "Failed to disable protection: $_"
                    exit 1
                }
            }
        }
    }
    
    Write-Host "`n=== Section: Recovery Key ==="
    # Apply recovery key action if not part of Enable process
    if ($BitLockerProtection -ne 'Enable') {
        Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction
        Get-VolumeObject  # Refresh volume state after recovery action
    }
    
    # Backup to AD if set
    if ($BackupToAD) {
        Write-Host "`n=== Section: AD Backup ==="
        Backup-KeyToAD -v $blv
    }
}

######################################
# END: Summary & Optional Auto-Reboot
######################################
end {
    Write-Host "`n=== Final Protectors ==="
    Log-Protectors -v $blv
    
    Write-Host "`n=== Section: Summary ==="
    Write-Log "SUCCESS" "BitLocker operations completed: Protection=$BitLockerProtection, Status=$($blv.ProtectionStatus), VolumeStatus=$($blv.VolumeStatus)"
    
    # Check for restart requirements only if applicable
    $restartMessage = Check-RestartRequirement -v $blv
    if ($restartMessage) {
        Write-Log "INFO" $restartMessage
    }
    
    # Additional check for decryption in progress
    if ($BitLockerProtection -eq 'Disable' -and $blv.VolumeStatus -eq 'DecryptionInProgress') {
        Write-Log "INFO" "Decryption is in progress. Avoid restarting until decryption is complete."
    }
    
    # Ensure a recovery key exists if protection is enabled or suspended
    if ($blv.ProtectionStatus -ne 'Off' -or ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyEncrypted')) {
        if (-not (Test-RecoveryPasswordPresent -v $blv -SuppressLog)) {
            Write-Log "WARNING" "BitLocker is enabled or suspended without a recovery key; adding one"
            Invoke-RecoveryAction -v $blv -Action 'Ensure' -SuppressLog
            # Refresh volume state after adding recovery key
            Get-VolumeObject
        }
    }
    
    # Update custom fields based on final state
    Write-Host "`n=== Section: Update Custom Fields ==="
    if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
        # Set fields to "N/A" when BitLocker is fully disabled
        Store-MountPoint -mountPoint "N/A"
        Store-ProtectionState -protectionState "N/A"
        Store-EncryptionMethod -encryptionMethod "N/A"
        Store-UsedSpaceOnly -usedSpaceOnly "N/A"
    }
    else {
        # Store actual values
        Store-MountPoint -mountPoint $MountPoint
        $desiredProtectionState = Get-DesiredProtectionState -action $BitLockerProtection
        Store-ProtectionState -protectionState $desiredProtectionState
        if ($blv.VolumeStatus -eq 'FullyEncrypted' -or $blv.VolumeStatus -eq 'EncryptionInProgress') {
            Store-EncryptionMethod -encryptionMethod $blv.EncryptionMethod
        }
        if ($finalEnableState -eq "enabled") {
            Store-UsedSpaceOnly -usedSpaceOnly $UseUsedSpaceOnly
        }
    }
    
    # Always call Store-RecoveryKey and Store-CurrentProtectors
    Store-RecoveryKey -v $blv
    Store-CurrentProtectors -v $blv
    
    # Schedule a reboot if AutoReboot is enabled and applicable
    if ($AutoReboot) {
        Write-Log "INFO" "AutoReboot enabled; scheduling reboot in $RebootDelay seconds"
        Start-Process shutdown -ArgumentList "/r /t $RebootDelay" -NoNewWindow
    }
}
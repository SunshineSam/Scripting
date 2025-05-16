#Requires -Version 5.1

<#
.SYNOPSIS
    Manage Bitlocker end-to-end and generate a status card for NinjaRMM.

.DESCRIPTION
    This script manages Bitlocker operations (enable, suspend, disable) on a specified volume,
    generates an HTML status card with Bitlocker details, and updates a NinjaRMM WYSIWYG custom field.
    The recovery key is stored separately in a secure custom field. Designed to run on a schedule
    for monitoring and management purposes.

.PARAMETER MountPoint
    Target drive letter or mount point (defaults to system drive or env:bitlockerMountPoint).

.PARAMETER BitLockerProtection
    Dropdown: Enable, Suspend, or Disable protection (required).

.PARAMETER RecoveryKeyAction
    Dropdown: Ensure, Rotate, or Remove numeric recovery key (required).

.PARAMETER BitlockerEncryptionMethod
    Dropdown: Aes128, Aes256, XtsAes128, or XtsAes256 Bitlocker encryption method (required).

.PARAMETER BackupToAD
    Switch to backup recovery keys to AD.

.PARAMETER AutoReboot
    Switch to reboot after Enable or Suspend.

.PARAMETER SuspensionRebootCount
    Number of reboots to allow for suspended protection (default 1).

.PARAMETER UseUsedSpaceOnly
    Set encryption for used space only.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to C:\Logs\BitLockerScript.log on the device.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the Bitlocker status card.
    Defaults to "BitLockerStatusCard" or env:bitLockerStatusFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.
#>

[CmdletBinding()]
param(
    # Drive letter (mount point)
    [string]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint } else { (Get-CimInstance Win32_OperatingSystem).SystemDrive }),
    
    # Dropdown options
    [ValidateSet("Enable", "Suspend", "Disable")][string]$BitLockerProtection = $(if ($env:bitlockerProtection) { $env:bitlockerProtection } else { "Enable" }),
    [ValidateSet("Ensure", "Rotate", "Remove")][string]$RecoveryKeyAction = $(if ($env:bitlockerRecoveryKeyAction) { $env:bitlockerRecoveryKeyAction } else { "Ensure" }),
    [ValidateSet("Aes128", "Aes256", "XtsAes128", "XtsAes256")][string]$BitlockerEncryptionMethod = $(if ($env:bitlockerEncryptionMethod) { $env:bitlockerEncryptionMethod } else { "XtsAes256" }),
    
    # Remaining independent switches
    [switch]$UseTpmProtector = $(if ($env:useBitlockerTpmProtector) { [Convert]::ToBoolean($env:useBitlockerTpmProtector) } else { $true }),
    [switch]$UseUsedSpaceOnly = $(if ($env:encryptUsedspaceonly) { [Convert]::ToBoolean($env:encryptUsedspaceonly) } else { $true }),
    [switch]$BackupToAD  = $(if ($env:bitlockerBackupToAd) { [Convert]::ToBoolean($env:bitlockerBackupToAd) } else { $false }),
    [switch]$AutoReboot = $(if ($env:bitlockerAutoReboot) { [Convert]::ToBoolean($env:bitlockerAutoReboot) } else { $false }),
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }),
    [int]$SuspensionRebootCount = $(if ($env:bitlockerSuspensionRebootCount) { [int]$env:bitlockerSuspensionRebootCount } else { 1 }),
    [int]$RebootDelay = 300,
    
    # Custom field names for NinjaRMM
    [string]$BitLockerStatusFieldName = $(if ($env:bitLockerStatusFieldName) { $env:bitLockerStatusFieldName } else { "BitLockerStatusCard" }),
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }),
    
    # Card customization options
    [string]$CardTitle = "Bitlocker Status",  # Default title
    [string]$CardIcon = "fas fa-shield-alt",  # Default icon
    [string]$CardBackgroundGradient = "Default",  # Gradiant not supported with Ninja. 'Default' omits the style.
    [string]$CardBorderRadius = "10px",  # Default border radius
    
    # Variable to ensure both TPM and Recovery Key protectors are always present (when true).
    [switch]$PreventKeyPromptOnEveryBoot = $(if ($env:preventKeyPromptOnEveryBoot) { [Convert]::ToBoolean($env:preventKeyPromptOnEveryBoot) } else { $true }),  # Set to $false to allow Bitlocker without TPM
    
    # Registry path for storing unretreivable states
    [string]$BitLockerStateManagementPath = $(if ($env:bitLockerStateManagementPath) { $env:bitLockerStateManagementPath } else { "HKLM:\SOFTWARE\BitLockerManagement" }),
    # Storing UsedSpaceOnly setting
    [string]$UsedSpaceOnlyStateValueName = $(if ($env:usedSpaceOnlyStateValueName) { $env:usedSpaceOnlyStateValueName } else { "UsedSpaceOnly" })
)

# =========================================
# BEGIN Block: Initialization & Validation
# =========================================
begin {
    
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Administrator privileges required"
        exit 1
    }
    Write-Host "Running as Administrator"
    
    Write-Host "`n=== Initialization & Validation ==="
    
    ##############
    # Validation #
    ##############
    
    # Validate MountPoint
    $MountPoint = $MountPoint.Trim()
    if ($MountPoint -notmatch '^[A-Za-z]:\\?$') {
        Write-Host "[ERROR] MountPoint '$MountPoint' must be a valid drive letter (e.g., 'C:')"
        exit 1
    }
    if (-not (Test-Path $MountPoint -PathType Container)) {
        Write-Host "[ERROR] MountPoint '$MountPoint' does not exist or is not a valid volume"
        exit 1
    }
    
    # Validate SuspensionRebootCount
    if ($SuspensionRebootCount -lt 0 -or $SuspensionRebootCount -gt 10) {
        Write-Host "[WARNING] SuspensionRebootCount must be between 0 and 10; setting to 1"
        $SuspensionRebootCount = 1
    }
    
    # Validate RebootDelay
    if ($RebootDelay -lt 0 -or $RebootDelay -gt 31536000) {
        Write-Host "[WARNING] RebootDelay must be between 0 and 31536000 seconds; setting to 500"
        $RebootDelay = 500
    }

    # Ensure AutoReboot aligns with Enable or Suspend
    if ($AutoReboot -and $BitLockerProtection -notin @("Enable", "Suspend")) {
        Write-Host "[WARNING] AutoReboot is true but incompatible with '$BitLockerProtection'; setting to false"
        $AutoReboot = $false
    }
    
    Write-Host "[SUCCESS] Dropdown values loaded:"
    Write-Host "  - Bitlocker Mount Point: $MountPoint"
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
            # Sublogic: If recovery key was set to remove and Bitlocker is Enabled/Suspeneded, set to Ensure. There will ALWAYS be a Bitlocker recovery key when enabled/suspened
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
        Write-Host "[INFO] PreventKeyPromptOnEveryBoot is false; skipping strict TPM and Recovery Key enforcement checks.`nThis may result in Bitlocker prompting during EVERY BOOT if you remove the TPM."
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
    
    # Bitlocker Protection Status sanitization
    if ($BitLockerProtection -eq "Disable") {
        Write-Host "[INFO] Protection action 'Disable' selected; validating possible conflicting settings"
        $BackupToAD = $false # disable AD backup
        if ($RecoveryKeyAction -in @("Ensure", "Rotate")) {
            Write-Host "[WARNING] RecoveryKeyAction was '$RecoveryKeyAction', but 'Disable' only allows 'Remove'. Setting RecoveryKeyAction to 'Remove'."
            $RecoveryKeyAction = "Remove"
        }
        else {
            Write-Host "[SUCCESS] RecoveryKeyAction is '$RecoveryKeyAction', compatible with 'Disable'"
        }
        if ($BackupToAD)
        {
            Write-Host "[WARNING] BackupToAD was '$BackupToAD', but 'Disable' only allows 'false'. Setting BackupToAD to 'false'."
            $BackupToAD = $false # disable AD backup
        }
        else {
            Write-Host "[SUCCESS] BackupToAD is '$BackupToAD', compatible with 'Disable'"
        }
    }
    
    Write-Host "[SUCCESS] Input sanitization completed successfully"

    #######################
    # Helper Functions
    #######################
    
    # Helper function: Create an info card with structured data and icon color
    function Get-NinjaOneInfoCard($Title, $Data, [string]$Icon, [string]$TitleLink, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor = "#000000") {
        <#
        .SYNOPSIS
            Creates an info card for display in NinjaRMM with customizable background gradient, border radius, and icon color.
        
        .DESCRIPTION
            Generates an HTML string for an info card displaying structured data with customizable styles and icon color.
        #>
        [System.Collections.Generic.List[String]]$ItemsHTML = @()
        foreach ($Item in $Data.PSObject.Properties) {
            $ItemsHTML.add('<p ><b >' + $Item.Name + '</b><br />' + $Item.Value + '</p>')
        }
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor
    }
    
    # Helper function: Generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor) {
        <#
        .SYNOPSIS
            Creates an HTML card for display in NinjaRMM with customizable background gradient, border radius, and icon color.
        
        .DESCRIPTION
            Generates an HTML string representing a card with a title, body, optional icon with color, title link, additional classes, background gradient, and border radius.
        #>
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background: $BackgroundGradient; border-radius: $BorderRadius;"
        $OutputHTML.add('<div class="card flex-grow-1' + $(if ($classes) { ' ' + $classes }) + '" style="' + $style + '">')
        if ($Title) {
            $iconHtml = if ($Icon) { '<i class="' + $Icon + '" style="color: ' + $IconColor + ';"></i> ' } else { '' }
            $OutputHTML.add('<div class="card-title-box"><div class="card-title" >' + $iconHtml + $Title + '</div>')
            if ($TitleLink) {
                $OutputHTML.add('<div class="card-link-box"><a href="' + $TitleLink + '" target="_blank" class="card-link" ><i class="fas fa-arrow-up-right-from-square" style="color: #337ab7;"></i></a></div>')
            }
            $OutputHTML.add('</div>')
        }
        $OutputHTML.add('<div class="card-body" >')
        $OutputHTML.add('<p class="card-text" >' + $Body + '</p>')
        $OutputHTML.add('</div></div>')
        return $OutputHTML -join ''
    }
    
    # Helper function: Define logging function for consistent output and optional file logging
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
    
    # Helper function: refresh drive state
    function Get-VolumeObject {
        try {
            # Sublogic: Retrieve Bitlocker volume object and suppress all non-error output
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
            Write-Log "ERROR" "No Bitlocker volume at ${MountPoint}: $_"
            exit 1
        }
    }
    
    # Helper function: detect if Bitlocker is awaiting key backup before activation. Usually occurs during first ever activation.
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
                Write-Log "INFO" "Bitlocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and or resuming protection."
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
                    Write-Log "INFO" "Bitlocker is encrypting (status: $($volume.VolumeStatus))."
                }
                elseif ($volume.VolumeStatus -eq 'FullyEncrypted' -and $volume.ProtectionStatus -eq 0) {
                    Write-Log "INFO" "Bitlocker is FullyEncrypted but Protection is Off. Consider checking recovery key is managed and or resuming protection."
                }
                elseif ($volume.ProtectionStatus -eq 'Off') {
                    if ($volume.VolumeStatus -eq 'DecryptionInProgress') {
                        Write-Log "INFO" "Bitlocker is decrypting the volume. Please wait until decryption is complete before restarting."
                    }
                    else {
                        $hasTpm = ($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' }).Count -gt 0
                        if ($hasTpm) {
                            Write-Log "INFO" "Bitlocker is Off with a TPM protector. Resume protection or reboot to finalize."
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
    
    # Helper function: manage the Bitlocker Recovery Key Action selection (See above 3 functions being called)
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
                    if (-not $SuppressLog) { Write-Log "WARNING" "Cannot remove recovery key when Bitlocker is enabled or suspended; skipping" }
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
    
    # Helper function: save key to AD & AAD when if applicable
    function Backup-KeyToAD {
        param($volume)
        Write-Log "INFO" "Determining backup location for recovery key"
    
        # Get BitLocker protectors
        $protectors = Get-ValidRecoveryProtectors -v $volume
        if (-not $protectors) {
            Write-Log "WARNING" "No numeric recovery protectors found; nothing to back up"
            return
        }
    
        # Check join status with dsregcmd.exe
        $DSRegOutput = [PSObject]::New()
        & dsregcmd.exe /status | Where-Object { $_ -match ' : ' } | ForEach-Object {
            $Item = $_.Trim() -split '\s:\s'
            $DSRegOutput | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $Item[1] -ErrorAction SilentlyContinue
        }
    
        # Backup logic based on join status
        if ($DSRegOutput.AzureADJoined -eq 'YES') {
            Write-Log "INFO" "Device is AAD-joined; backing up to AAD"
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AAD"
                try {
                    BackupToAAD-BitLockerKeyProtector `
                        -MountPoint $volume.MountPoint `
                        -KeyProtectorId $keypair.KeyProtectorId `
                        -ErrorAction Stop
                    Write-Log "SUCCESS" "Protector ID $($keypair.KeyProtectorId) backed up to AAD"
                }
                catch {
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AAD: $_"
                }
            }
        }
        elseif ($DSRegOutput.DomainJoined -eq 'YES') {
            Write-Log "INFO" "Device is domain-joined; backing up to AD"
            foreach ($keypair in $protectors) {
                Write-Log "INFO" "Backing up protector ID $($keypair.KeyProtectorId) to AD"
                try {
                    Backup-BitLockerKeyProtector `
                        -MountPoint $volume.MountPoint `
                        -KeyProtectorId $keypair.KeyProtectorId `
                        -ErrorAction Stop
                    Write-Log "SUCCESS" "Protector ID $($keypair.KeyProtectorId) backed up to AD"
                }
                catch {
                    Write-Log "ERROR" "Failed to back up protector $($keypair.KeyProtectorId) to AD: $_"
                }
            }
        }
        else {
            Write-Log "WARNING" "Device is not joined to AD or AAD; skipping backup"
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
                Write-Log "INFO" "Bitlocker enabled with TPM and recovery key protectors. No restart required."
            }
            elseif ($hasTpm) {
                Write-Log "WARNING" "Restart required to complete Bitlocker setup with TPM."
            }
        }
        elseif ($volume.ProtectionStatus -eq 'On' -and $volume.VolumeStatus -eq 'EncryptionInProgress') {
            Write-Log "INFO" "Restart may be beneficial to speed up encryption process."
        }
        return $null
    }
    
    # Helper function: Validate TPM state and system configuration
    function Validate-BitLockerState {
        param($volume)
        # Sublogic: Check for pending reboots
        $rebootPending = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if ($rebootPending) {
            Write-Log "WARNING" "A system reboot is pending, which may affect Bitlocker configuration. A reboot is recommended after changes have been made."
        }
        
        # Sublogic: Check TPM status
        try {
            $tpm = Get-Tpm
            if ($tpm.TpmPresent -and !$tpm.TpmReady) {
                Write-Log "WARNING" "TPM is present but not ready. This may cause Bitlocker to enter recovery mode during the next boot."
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
            Write-Log "WARNING" "No protectors configured for volume. Bitlocker will not function until protectors are added."
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
            Write-Log "INFO" "Attempting to store recovery key protector"
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

# =========================================
# PROCESS Block: Execute Bitlocker Actions
# =========================================
process {
    
    # Proccess output for understanding
    Write-Log "INFO" "Starting Bitlocker management and status card generation"
    
    # State management variables
    $script:NumericProtectorCreated = $false
    $script:LastLogContext = @{}
    $script:LoggedRecoveryFound = @{}
    
    Write-Host "`n=== Section: Volume Detection ==="
    Write-Log "INFO" "Retrieving Bitlocker volume for $MountPoint"
    
    # Update the volume state
    Get-VolumeObject
    
    # Track initial protection status from the Get-VolumeObject call
    $script:initialProtectionStatus = $blv.ProtectionStatus
    
    Write-Host "`n=== Section: Protection State Check ==="
    # Validate Bitlocker and TPM state
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
                    Write-Log "WARNING" "Cannot suspend — Bitlocker is not yet enabled."
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
            Write-Log "INFO" "Bitlocker is not enabled and no TPM protector is pending."
        }
    }
    elseif ($blv.ProtectionStatus -eq 2) {
        Write-Log "INFO" "Bitlocker is in a suspended state."
    }
    
    Write-Host "`n=== Section: Protection (using: $BitLockerProtection) ==="

    # TPM availability safety check
    try {
        $tpm = Get-Tpm
        $tpmAvailable = $tpm.TpmPresent -and $tpm.TpmReady
    }
    catch {
        $tpmAvailable = $false
    }

    if (-not $tpmAvailable -and $PreventKeyPromptOnEveryBoot) {
        Write-Output "TPM is not available and PreventKeyPromptOnEveryBoot is true. Exiting script."
        exit 1
    }
    elseif (-not $tpmAvailable) {
        Write-Warning "TPM is not available, but PreventKeyPromptOnEveryBoot is false. Continuing without TPM."
    }   
    
    # Manage the switch case logic for the Bitlocker ptotection selection
    switch ($BitLockerProtection) {
        'Enable' {
            Write-Log "INFO" "Requested: Enable/Resume protection"
            if ($blv.ProtectionStatus -eq 2) {
                Write-Log "INFO" "Bitlocker is suspended; resuming protection"
                if ($PreventKeyPromptOnEveryBoot) {
                    Ensure-TpmProtector -v $blv
                    # Respect user-specified RecoveryKeyAction (e.g., 'Rotate')
                    Invoke-RecoveryAction -v $blv -Action $RecoveryKeyAction -SuppressLog
                    Get-VolumeObject  # Refresh volume object after recovery action
                }
                try {
                    Resume-Bitlocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
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
                        Resume-Bitlocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
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
                        Resume-Bitlocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
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
                    Write-Log "INFO" "Enabling Bitlocker with -UsedSpaceOnly"
                }
                else {
                    Write-Log "INFO" "Enabling Bitlocker without -UsedSpaceOnly (full disk encryption)"
                }
                
                # Enable Bitlocker with RecoveryPasswordProtector
                Write-Log "INFO" "Enabling Bitlocker with Recovery Password protector"
                try {
                    Enable-Bitlocker `
                        -MountPoint $MountPoint `
                        -EncryptionMethod $BitlockerEncryptionMethod `
                        -RecoveryPasswordProtector `
                        -SkipHardwareTest `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue `
                        -InformationAction SilentlyContinue `
                        -UsedSpaceOnly:$UseUsedSpaceOnly | Out-Null
                    Write-Log "SUCCESS" "Bitlocker enabled with recovery key protector"
                    Get-VolumeObject
                    
                    # Write UsedSpaceOnly setting to registry
                    $usedSpaceOnlyText = if ($UseUsedSpaceOnly) { 'Yes' } else { 'No' }
                    if (-not (Test-Path $BitLockerStateManagementPath)) {
                        New-Item -Path $BitLockerStateManagementPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $BitLockerStateManagementPath -Name $UsedSpaceOnlyStateValueName -Value $usedSpaceOnlyText -Type String -Force
                    Write-Log "INFO" "Stored UsedSpaceOnly setting in registry: $usedSpaceOnlyText"
                }
                catch {
                    Write-Log "ERROR" "Failed to enable Bitlocker: $_"
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
                        Resume-Bitlocker -MountPoint $MountPoint -ErrorAction Stop | Out-Null
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
                        Write-Log "INFO" "Bitlocker protection successfully resumed"
                    }
                    'enabled' {
                        if ($blv.VolumeStatus -eq 'EncryptionInProgress' -or $blv.VolumeStatus -eq 'EncryptionPaused') {
                            Write-Log "INFO" "Bitlocker is encrypting (status: $($blv.VolumeStatus))."
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
                Write-Log "WARNING" "Cannot suspend — Bitlocker is currently encrypting the volume."
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
                    Suspend-Bitlocker -MountPoint $MountPoint -RebootCount $SuspensionRebootCount -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
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
                    Disable-Bitlocker -MountPoint $MountPoint -ErrorAction Stop -InformationAction SilentlyContinue | Out-Null
                    Write-Log "SUCCESS" "Decryption initiated"
                    Get-VolumeObject
                }
                catch {
                    Write-Log "ERROR" "Failed to disable protection: $_"
                    exit 1
                }
            }
            # Set registry to "Disabled" to reflect the disabled state
            if (-not (Test-Path $BitLockerStateManagementPath)) {
                New-Item -Path $BitLockerStateManagementPath -Force | Out-Null
            }
            Set-ItemProperty -Path $BitLockerStateManagementPath -Name $UsedSpaceOnlyStateValueName -Value "N/A" -Type String -Force
            Write-Log "INFO" "Set UsedSpaceOnly registry to 'N/A'"
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

# =========================================
# END Block: Generate Card & Finalization
# =========================================
end {
    Write-Host "`n=== Section: Generate Status Card ==="
    Get-VolumeObject  # Refresh volume object to reflect final state
    
    # Determine title icon and color based on Bitlocker state
    switch ($blv.ProtectionStatus) {
        'On' {
            switch ($blv.VolumeStatus) {
                'FullyEncrypted' {
                    # Shield for fully protected
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#26A644"  # Green
                }
                'EncryptionInProgress' {
                    # Shield for encrypting
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#F0AD4E"  # Yellow
                }
                default {
                    # Shield for other 'On' states
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#F0AD4E"  # Yellow
                }
            }
        }
        'Suspended' {
            # Shield for suspended
            $CardIcon = "fas fa-shield-alt"
            $CardIconColor = "#F0AD4E"  # Yellow
        }
        'Off' {
            switch ($blv.VolumeStatus) {
                'DecryptionInProgress' {
                    # Shield for decrypting
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#D9534F"  # Red
                }
                'FullyDecrypted' {
                    # Shield for fully decrypted
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#D9534F"  # Red
                }
                default {
                    # Shield for other 'Off' states
                    $CardIcon = "fas fa-shield-alt"
                    $CardIconColor = "#F0AD4E"  # Yellow
                }
            }
        }
        default {
            # Shield for unknown states
            $CardIcon = "fas fa-shield-alt"
            $CardIconColor = "#F0AD4E"  # Yellow
        }
    }

    # Generate protection status with icon
    $protectionStatusHtml = switch ($blv.ProtectionStatus) {
        'On' { 
            # Green check circle for active protection
            '<i class="fas fa-check-circle" style="color:#26A644;"></i> On' 
        }
        'Off' { 
            # Red times circle for no protection
            '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Off' 
        }
        'Suspended' { 
            # Yellow pause circle for suspended protection
            '<i class="fas fa-pause-circle" style="color:#F0AD4E;"></i> Suspended' 
        }
        default { 
            # Plain text for unknown protection status
            $blv.ProtectionStatus 
        }
    }

    # Generate volume status with icon
    $volumeStatusHtml = switch ($blv.VolumeStatus) {
        'FullyEncrypted' { 
            # Green lock for fully encrypted volume
            '<i class="fas fa-lock" style="color:#26A644;"></i> Fully Encrypted' 
        }
        'EncryptionInProgress' { 
            # Yellow spinner for encryption in progress
            '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Encryption in Progress' 
        }
        'FullyDecrypted' { 
            # Red unlock for fully decrypted volume
            '<i class="fas fa-unlock" style="color:#D9534F;"></i> Fully Decrypted' 
        }
        'DecryptionInProgress' { 
            # Yellow spinner for decryption in progress
            '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Decryption in Progress' 
        }
        default { 
            # Plain text for unknown volume status
            $blv.VolumeStatus 
        }
    }
    
    # Get encryption method or 'N/A'
    $encryptionMethod = if ($blv.EncryptionMethod) { $blv.EncryptionMethod } else { 'N/A' }
    
    # Get protectors or 'None'
    $protectors = if ($blv.KeyProtector) { ($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " } else { 'None' }
    
    # Determine UsedSpaceOnly display value
    if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
        $usedSpaceOnlyDisplay = "N/A"
    }
    else {
        try {
            # Read the value
            $value = Get-ItemPropertyValue -Path $BitLockerStateManagementPath -Name $UsedSpaceOnlyStateValueName -ErrorAction Stop
            Write-Log "DEBUG" "Successfully read ${UsedSpaceOnlyStateValueName}: '$value'"
            if ($value -in @("Yes", "No")) {
                $usedSpaceOnlyDisplay = $value
            }
            else {
                $usedSpaceOnlyDisplay = "Unknown"
                Write-Log "WARNING" "Invalid value for ${UsedSpaceOnlyStateValueName}: '$value'. Expected 'Yes' or 'No'."
            }
        }
        catch {
            $usedSpaceOnlyDisplay = "Unknown"
            Write-Log "DEBUG" "Failed to read registry: $_"
        }
        # Log if we end up with Unknown
        if ($usedSpaceOnlyDisplay -eq "Unknown") {
            Write-Log "WARNING" "Encrypt Used Space Only is ${usedSpaceOnlyDisplay}.`n Used Space Only state will be stored and read when enabling Bitlocker from a disabled state with the Bitlocker Management automation."
        }
    }
    
    # Create Bitlocker info object with UsedSpaceOnly always included
    $bitlockerInfo = [PSCustomObject]@{
        'Protection Status'       = $protectionStatusHtml
        'Volume Status'           = $volumeStatusHtml
        'Mount Point'             = $MountPoint
        'Encryption Method'       = $encryptionMethod
        'Protectors'              = $protectors
        'Encrypt Used Space Only' = $usedSpaceOnlyDisplay
    }
    
    # Generate HTML card with dynamic title, icon, and calculated icon color
    $cardHtml = Get-NinjaOneInfoCard -Title $CardTitle -Data $bitlockerInfo -Icon $CardIcon -BackgroundGradient $CardBackgroundGradient -BorderRadius $CardBorderRadius -IconColor $CardIconColor
    
    # Store the card in the custom field
    try {
        $cardHtml | Ninja-Property-Set-Piped -Name $BitLockerStatusFieldName
        Write-Log "SUCCESS" "Bitlocker status card stored in '$BitLockerStatusFieldName'"
    }
    catch {
        Write-Log "ERROR" "Failed to store status card: $_"
    }
    
    # Store the recovery key
    Store-RecoveryKey -v $blv

    # Schedule a reboot if AutoReboot is enabled and applicable
    if ($AutoReboot) {
        Write-Log "INFO" "AutoReboot enabled; scheduling reboot in $RebootDelay seconds"
        Start-Process shutdown -ArgumentList "/r /t $RebootDelay" -NoNewWindow
    }
    
    Write-Log "INFO" "Bitlocker management and status card generation completed"
}
#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieve Bitlocker information and update the NinjaRMM status card.

.DESCRIPTION
    This script retrieves key Bitlocker details for a specified mount point, generates an HTML status card,
    and updates a NinjaRMM custom field. Optionally, it can update the recovery key in a secure field if the
    updateRecoveryKey flag is enabled. It is designed to run on a schedule for monitoring purposes, using 
    environment variables as a fallback for configuration.

.PARAMETER MountPoint
    The drive letter or mount point to check (e.g., 'C:'). Defaults to the system drive or env:bitlockerMountPoint if set.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to C:\Logs\BitLockerInfo.log on the device.

.PARAMETER UpdateRecoveryKey
    If specified, searches for and stores the active recovery key protector in the secure field. Can be set via env:updateRecoveryKey.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the Bitlocker status card.
    Defaults to "BitLockerStatusCard" or env:bitlockerStatusCardWysiwygFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.
#>

[CmdletBinding()]
param(
    # Drive letter or mount point, with fallback to environment variable or system drive
    [string]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint } else { (Get-CimInstance Win32_OperatingSystem).SystemDrive }),

    # New parameter to control recovery key update
    [switch]$UpdateRecoveryKey = $(if ($env:updateRecoveryKey) { [Convert]::ToBoolean($env:updateRecoveryKey) } else { $false }),
    # Switch to enable logging to a file on the device
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }),
    
    # Custom field names for NinjaRMM with default value fallback
    [string]$BitLockerStatusFieldName = $(if ($env:bitlockerStatusCardWysiwygFieldName) { $env:bitlockerStatusCardWysiwygFieldName } else { "BitLockerStatusCard" }),
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }),

    # Card customization options
    [string]$CardTitle = "Bitlocker Status",  # Default Card title
    [string]$CardIcon = "fas fa-shield-alt",  # Default Card icon
    [string]$CardBackgroundGradient = "Default",  # Gradiant not supported with Ninja. 'Default' omitts the style.
    [string]$CardBorderRadius = "10px"  # Default Card border radius

    # CardIconColor is dynamically generated in this case
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

    # Validate MountPoint
    $MountPoint = $MountPoint.Trim()
    if ($MountPoint -notmatch '^[A-Za-z]:\\?$') {
        Write-Host "[ERROR] MountPoint '$MountPoint' must be a valid drive letter (e.g., 'C:' or 'C:\\')"
        exit 1
    }
    if (-not (Test-Path $MountPoint -PathType Container)) {
        Write-Host "[ERROR] MountPoint '$MountPoint' does not exist or is not a valid volume"
        exit 1
    }

    Write-Host "[SUCCESS] Parameters validated:"
    Write-Host "  - Mount Point: $MountPoint"

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
            $logFile = Join-Path $logDir "BitLockerInfo.log"
            
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
            Write-Log "SUCCESS" "Volume state refreshed: ProtectionStatus=$($blv.ProtectionStatus), VolumeStatus=$($blv.VolumeStatus)"
        }
        catch {
            Write-Log "ERROR" "No Bitlocker volume at ${MountPoint}: $_"
            exit 1
        }
    }

    # Define helper function to create an info card with structured data and icon color
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

    # Helper function to generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor) {
        <#
        .SYNOPSIS
            Creates an HTML card for display in NinjaRMM with customizable background gradient, border radius, and icon color.

        .DESCRIPTION
            Generates an HTML string representing a card with a title, body, optional icon with color, title link, additional classes, background gradient, and border radius.
        #>
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background-color: $BackgroundGradient; border-radius: $BorderRadius;"
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

    # Helper function: return the list of valid protectors; list
    function Get-ValidRecoveryProtectors {
        param($volume)
        # Only log the scan message if this is the top-level call
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

    # Helper function: store recovery key, set secure field to 'N/A' if Bitlocker is fully disabled
    function Store-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Attempting to store current recovery key in secure field"
        
        # Sublogic: Check if there are no protectors and the volume is fully disabled
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
        
        # Sublogic: Retry loop to detect the recovery key
        do {
            Get-VolumeObject  # Refresh volume object each attempt
            $protectors = Get-ValidRecoveryProtectors -v $volume
            if ($protectors) {
                Write-Log "INFO" "Detected recovery key on attempt $($retryCount + 1)"
                break
            }
            else {
                Write-Log "WARNING" "No recovery key protectors detected on attempt $($retryCount + 1); retrying in $retryDelay seconds"
            }
            Start-Sleep -Seconds $retryDelay
            $retryCount++
        }
        while ($retryCount -lt $maxRetries)
        
        # Sublogic: Store the latest key if available
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
            Write-Log "WARNING" "No recovery key protectors found after $maxRetries retries; setting to 'No Recovery Key'"
            try {
                Ninja-Property-Set $RecoveryKeySecureFieldName "No Recovery Key" | Out-Null
                Write-Log "SUCCESS" "Recovery key set to 'No Recovery Key' in secure field '$RecoveryKeySecureFieldName'"
            }
            catch {
                Write-Log "ERROR" "Failed to set recovery key field: $_"
            }
        }
    }

    Write-Log "INFO" "Starting Bitlocker information retrieval for mount point: $MountPoint"
}

# =========================================
# PROCESS Block: Retrieve and Store Bitlocker Information
# =========================================
process {
    try {
        Write-Host "`n=== Section: Volume Status ==="
        # Retrieve the Bitlocker volume
        Get-VolumeObject

        # Update recovery key if the flag is enabled
        if ($UpdateRecoveryKey) {
            Write-Log "INFO" "UpdateRecoveryKey enabled; attempting to store recovery key"
            Store-RecoveryKey -volume $blv
        }

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

        Write-Host "`n=== Section: Protection Detection ==="
        # Get encryption method or 'N/A'
        $encryptionMethod = if ($blv.EncryptionMethod) { $blv.EncryptionMethod } else { 'N/A' }
        
        # Get protectors or 'None'
        $protectors = if ($blv.KeyProtector) { ($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " } else { 'None' }
        
        # Registry path and value name
        $BitLockerStateManagementPath = "HKLM:\SOFTWARE\BitLockerManagement"
        $UsedSpaceOnlyStateValueName = "UsedSpaceOnly"

        # Registry path and value name
        $BitLockerStateManagementPath = "HKLM:\SOFTWARE\BitLockerManagement"
        $UsedSpaceOnlyStateValueName = "UsedSpaceOnly"
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

        # Create Bitlocker info object with all current states
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
    }
    catch {
        Write-Log "ERROR" "Failed to retrieve Bitlocker volume for ${MountPoint}: $_"
    }
}

# =========================================
# END Block: Finalization
# =========================================
end {
    Write-Log "INFO" "Bitlocker information retrieval and status card generation completed"
}
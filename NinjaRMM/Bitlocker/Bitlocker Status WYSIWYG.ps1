#Requires -Version 5.1
<#
    === Created by Sam ===
    Last Edit: 05-23-2025

    Note:
    05-23-2025: Simplified status only reporting for multi volume (and card) support
    05-19-2025: General cleanup improvements (from original)
    04-25-2025: Creation and validation testing (from original)
#>

<#
.SYNOPSIS
    Generate HTML status cards for BitLocker on specified drives or all fixed disks for NinjaRMM.

.DESCRIPTION
    This script generates status reports for BitLocker on multiple drives or all fixed disks and publishes the status cards to NinjaRMM. Designed for scheduled running, it includes an option to override and report BitLocker recovery keys.

.PARAMETER ApplyToAllFixedDisk
    Switch. If set, targets all fixed disks in the system.

.PARAMETER MountPoint
    Target specific drive letter(s). Example: C:, D: (or defaults to system drive).

.PARAMETER UpdateRecoveryKeys
    Switch. If set, retrieves and reports the latest BitLocker recovery key for each volume.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to <SystemDrive>:\Logs\BitLockerScript.log on the device.

.PARAMETER BitLockerStatusFieldName
    The name of the NinjaRMM custom field to update with the BitLocker status card.
    Defaults to "BitLockerStatusCard" or env:bitLockerStatusFieldName.

.PARAMETER RecoveryKeySecureFieldName
    The name of the secure NinjaRMM custom field for the recovery key.
    Defaults to "BitLockerRecoveryKey" or env:recoveryKeySecureFieldName.
#>

[CmdletBinding()]
param(
    # Drive letter (mount point)
    [string[]]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint -split ',' } else { @((Get-CimInstance Win32_OperatingSystem).SystemDrive) }),
    
    # Remaining independent switches
    [switch]$ApplyToAllFixedDisk = $(if ($env:applyToAllFixedDisk) { [Convert]::ToBoolean($env:applyToAllFixedDisk) } else { $true }),
    [switch]$UpdateRecoveryKeys = $(if ($env:updateRecoveryKeys) { [Convert]::ToBoolean($env:updateRecoveryKeys) } else { $false }),
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }),
    
    # Custom field names for NinjaRMM
    [string]$BitLockerStatusFieldName = $(if ($env:bitLockerStatusFieldName) { $env:bitLockerStatusFieldName } else { "BitLockerStatusCard" }),
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" }),
    
    # Card customization options
    [string]$CardTitle = "Bitlocker Status",  # Default title
    [string]$CardIcon = "fas fa-shield-alt",  # Default icon
    [string]$CardBackgroundGradient = "Default",  # Gradient not supported with NinjaRMM. 'Default' omits the style.
    [string]$CardBorderRadius = "10px",  # Default border radius
    [string]$CardSeparationMargin = "0 8px", # Default distance between cards

    # Registry path for storing unretreivable states
    [string]$BitLockerStateStoragePath = $(if ($env:bitLockerStateStoragePath) { $env:bitLockerStateStoragePath } else { "HKLM:\SOFTWARE\BitLockerManagement" }),
    # Storing UsedSpaceOnly setting
    [string]$UsedSpaceOnlyStateValueName = $(if ($env:usedSpaceOnlyStateValueName) { $env:usedSpaceOnlyStateValueName } else { "UsedSpaceOnly" })
)

# =========================================
# BEGIN Block: Initialization & Validation
# =========================================
begin {
    
    # Immediate check if running with administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`nAdministrator privileges required"
        exit 1
    }
    Write-Host "`nRunning as Administrator"
    
    ##############
    # Validation #
    ##############

    Write-Host "`n=== Initialization & Validation ==="

    # Helper Function: Called early to check for drive dependencies (e.g., RAID or spanned volumes)
    function Test-DriveDependencies {
        Write-Host "[INFO] Checking for drive dependencies that may affect BitLocker operations"
        try {
            $physicalDisks = Get-PhysicalDisk
            $disks = Get-Disk
            foreach ($disk in $disks) {
                if ($disk.OperationalStatus -eq 'RAID' -or $disk.PartitionStyle -eq 'Unknown') {
                    Write-Host "[WARNING] Detected RAID or non-standard disk configuration on Disk $($disk.Number). BitLocker operations may fail."
                }
                if ($disk.IsBoot -and $disk.NumberOfPartitions -gt 1) {
                    Write-Host "[INFO] Multiple partitions detected on boot disk. Ensure BitLocker is applied to the correct volume."
                }
            }
            $spannedVolumes = Get-Volume | Where-Object { $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' } | 
                Where-Object { (Get-Partition -Volume $_).DiskNumber.Count -gt 1 }
            if ($spannedVolumes) {
                Write-Host "[WARNING] Detected spanned volumes: $($spannedVolumes.DriveLetter -join ', '). BitLocker may not support these configurations."
            }
            Write-Host "[SUCCESS] Drive dependency check completed"
        }
        catch {
            Write-Host "[ERROR] Failed to check drive dependencies: $_"
        }
    }
    # Immediately call drive dependency check
    Test-DriveDependencies
    
    # Handle ApplyToAllFixedDisk, otherwise parse MountPoint
    if ($ApplyToAllFixedDisk) {
        Write-Host "[INFO] ApplyToAllFixedDisk is set; retrieving all fixed disks"
        $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | 
            Select-Object -ExpandProperty DriveLetter | ForEach-Object { $_ + ':' }
        if (-not $drives) {
            Write-Host "[ERROR] No fixed disks found on this system"
            exit 1
        }
        Write-Host "[INFO] Found fixed disks: $($drives -join ', ')"
    }
    else {
        # Parse MountPoint for multiple drives
        $mountPoints = $MountPoint -split ',' | ForEach-Object { $_.Trim() }
        $drives = @()
        foreach ($mp in $mountPoints) {
            # Regex to match single letter (e.g., 'C') or letter with colon and optional backslash (e.g., 'C:' or 'C:\')
            if ($mp -match '^[A-Za-z]$' -or $mp -match '^[A-Za-z]:\\?$') {
                # If single letter, append colon; otherwise normalize by replacing trailing backslash with colon
                if ($mp -match '^[A-Za-z]$') {
                    $mp = $mp + ':'
                }
                else {
                    $mp = $mp -replace '\\$', ':'
                }
                # Fixed Disk safety check
                if (Test-Path $mp -PathType Container) {
                    $driveInfo = Get-Volume -DriveLetter $mp[0] -ErrorAction SilentlyContinue
                    if ($driveInfo -and $driveInfo.DriveType -eq 'Fixed') {
                        $drives += $mp
                    }
                    else {
                        Write-Host "[WARNING] MountPoint '$mp' is not a fixed disk; skipping"
                    }
                }
                else {
                    Write-Host "[WARNING] MountPoint '$mp' does not exist or is not a valid volume"
                }
            }
            else {
                # Updated message to reflect that both 'C' and 'C:' are accepted
                Write-Host "[WARNING] Invalid MountPoint format: '$mp'. Must be a drive letter like 'C' or 'C:'"
            }
        }
        if (-not $drives) {
            Write-Host "[ERROR] No valid fixed disks specified in MountPoint"
            exit 1
        }
    }
    
    Write-Host "[SUCCESS] Values loaded:"
    # Dynamic MountPoint message
    if ($ApplyToAllFixedDisk) {
        Write-Host "  - Bitlocker Mount Point(s): Ignored (ApplyToAllFixedDisk is true)"
    }
    else {
        Write-Host "  - Bitlocker Mount Point(s): $($MountPoint -join ', ')"
    }
    Write-Host "  - Override Recovery Key: $UpdateRecoveryKeys"
    
    # Initialize collection for processed volumes and recovery keys
    $script:ProcessedVolumes = @()
    $script:RecoveryKeys = @{}
    
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
        return Get-NinjaOneCard -Title $Title -Body ($ItemsHTML -join '') -Icon $Icon -TitleLink $TitleLink -BackgroundGradient $BackgroundGradient -BorderRadius $BorderRadius -IconColor $IconColor -SeparationMargin $CardSeparationMargin
    }
    
    # Helper function: Generate the HTML card with icon color support
    function Get-NinjaOneCard($Title, $Body, [string]$Icon, [string]$TitleLink, [string]$Classes, [string]$BackgroundGradient, [string]$BorderRadius, [string]$IconColor, [string]$SeparationMargin) {
        <#
        .SYNOPSIS
            Creates an HTML card for display in NinjaRMM with customizable background gradient, border radius, and icon color.
        
        .DESCRIPTION
            Generates an HTML string representing a card with a title, body, optional icon with color, title link, additional classes, background gradient, border radius, and margin.
        #>
        [System.Collections.Generic.List[String]]$OutputHTML = @()
        $style = "background: $BackgroundGradient; border-radius: $BorderRadius; margin: $SeparationMargin;"
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
            
            # Use the system drive for logging
            $systemDrive = (Get-CimInstance Win32_OperatingSystem).SystemDrive
            $logDir = "$systemDrive\Logs\BitLocker"
            $logFile = Join-Path $logDir "BitLockerStatus.log"
            
            # Sublogic: Create the log directory if it doesn't exist
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

    # Helper function: Refresh drive state
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
                Write-Host "[SUCCESS] Volume state refreshed: ProtectionStatus=$($blv.ProtectionStatus), VolumeStatus=$($blv.VolumeStatus)"
                $script:LastLogContext["VolumeState-$MountPoint"] = $true
            }
        }
        catch {
            Write-Log "ERROR" "No BitLocker volume at ${MountPoint}: $_"
            exit 1
        }
    }

    # Helper Function: Safe variable management 
    function Clear-Memory {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string[]]$VariableNames
        )
        foreach ($name in $VariableNames) {
            # Null out the variable
            Set-Variable -Name $name -Value $null -Scope Local -ErrorAction SilentlyContinue
            # Remove it entirely
            Clear-Variable -Name $name -Scope Local -ErrorAction SilentlyContinue
        }
        # No Write-Log output for safety
        Write-Host "[INFO] Cleared memory for variables: $($VariableNames -join ', ')"
    }

    # Helper function: Collect recovery key for reporting (simplified from management script)
    function Store-RecoveryKey {
        param($volume)
        Write-Log "INFO" "Collecting recovery key for $($volume.MountPoint)"
        
        # Check if there are no protectors and the volume is fully disabled
        if (-not $volume.KeyProtector -and $volume.ProtectionStatus -eq 'Off' -and $volume.VolumeStatus -eq 'FullyDecrypted') {
            Write-Log "INFO" "No protectors and volume is fully disabled; recording 'N/A' for $($volume.MountPoint)"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - N/A"
            return
        }
        
        $protectors = $volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if (-not $protectors) {
            Write-Log "WARNING" "No recovery key protectors found for $($volume.MountPoint); recording 'None'"
            $script:RecoveryKeys[$volume.MountPoint] = "Drive: $($volume.MountPoint) - None"
            return
        }
        
        $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
        $keyInfo = "$($volume.MountPoint) - Protector ID: $($latestProtector.KeyProtectorId) | Recovery Key: $($latestProtector.RecoveryPassword)"
        Write-Log "INFO" "Collected recovery key for $($volume.MountPoint)"
        $script:RecoveryKeys[$volume.MountPoint] = $keyInfo
        # Clear sensitive param per call
        Clear-Memory -VariableNames "keyInfo"
    }
}

# =========================================
# PROCESS Block: Collect Status Information
# =========================================
process {
    Write-Log "INFO" "Starting BitLocker status collection for all specified drives"
    
    # State management variables (reset for each run)
    $script:LastLogContext = @{}
    $script:ProcessedVolumes = @()
    
    Write-Host "`n=== Drive Processing ==="
    # Process each drive
    foreach ($MountPoint in $drives) {
        Write-Log "INFO" "Processing drive $MountPoint"
        
        # Update the volume state
        Get-VolumeObject
        
        # Collect recovery key if override is enabled
        if ($UpdateRecoveryKeys) {
            Store-RecoveryKey -volume $blv
        }
        
        # Store volume object for END block
        $script:ProcessedVolumes += ,$blv
        
        # Separate each volume in output
        Write-Host ""
    }
}

# =========================================
# END Block: Generate Card & Finalization
# =========================================
end {
    # Will always have a line space from above
    Write-Host "=== BitLocker Card Generation ==="
    Write-Log "INFO" "Generating status card for all processed drives"
    
    # Initialize combined HTML for all cards
    $allCardsHtml = ""
    if (-not $script:ProcessedVolumes) { $script:ProcessedVolumes = @() }
    
    foreach ($volume in $script:ProcessedVolumes) {
        $MountPoint = $volume.MountPoint
        Get-VolumeObject  # Refresh volume object
        
        # Determine title icon and color
        switch ($blv.ProtectionStatus) {
            'On' {
                switch ($blv.VolumeStatus) {
                    'FullyEncrypted' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#26A644" }
                    'EncryptionInProgress' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                    default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                }
            }
            'Suspended' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
            'Off' {
                switch ($blv.VolumeStatus) {
                    'DecryptionInProgress' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                    'FullyDecrypted' { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#D9534F" }
                    default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
                }
            }
            default { $CardIcon = "fas fa-shield-alt"; $CardIconColor = "#F0AD4E" }
        }
        
        # Generate protection and volume status HTML
        $protectionStatusHtml = switch ($blv.ProtectionStatus) {
            'On' { '<i class="fas fa-check-circle" style="color:#26A644;"></i> On' }
            'Off' { '<i class="fas fa-times-circle" style="color:#D9534F;"></i> Off' }
            'Suspended' { '<i class="fas fa-pause-circle" style="color:#F0AD4E;"></i> Suspended' }
            default { $blv.ProtectionStatus }
        }
        $volumeStatusHtml = switch ($blv.VolumeStatus) {
            'FullyEncrypted' { '<i class="fas fa-lock" style="color:#26A644;"></i> Fully Encrypted' }
            'EncryptionInProgress' { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Encryption in Progress' }
            'FullyDecrypted' { '<i class="fas fa-unlock" style="color:#D9534F;"></i> Fully Decrypted' }
            'DecryptionInProgress' { '<i class="fas fa-spinner" style="color:#F0AD4E;"></i> Decryption in Progress' }
            default { $blv.VolumeStatus }
        }
        
        $encryptionMethod = if ($blv.EncryptionMethod) { $blv.EncryptionMethod } else { 'N/A' }
        $protectors = if ($blv.KeyProtector) { ($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", " } else { 'None' }

        # Determine UsedSpaceOnly display value
        if ($blv.ProtectionStatus -eq 'Off' -and $blv.VolumeStatus -eq 'FullyDecrypted') {
            $usedSpaceOnlyDisplay = "N/A"
        }
        else {
            try {
                $value = Get-ItemPropertyValue -Path $BitLockerStateStoragePath -Name "$UsedSpaceOnlyStateValueName $MountPoint" -ErrorAction Stop
                $usedSpaceOnlyDisplay = if ($value -in @("Yes", "No")) { $value } else { "Unknown" }
            }
            catch {
                $usedSpaceOnlyDisplay = "Unknown"
            }
        }
        
        $bitlockerInfo = [PSCustomObject]@{
            'Protection Status'       = $protectionStatusHtml
            'Volume Status'           = $volumeStatusHtml
            'Volume'                  = $MountPoint
            'Encryption Method'       = $encryptionMethod
            'Protectors'              = $protectors
            'Encrypt Used Space Only' = $usedSpaceOnlyDisplay
        }
        
        # Generate card for this drive
        $cardHtml = Get-NinjaOneInfoCard -Title "$CardTitle ($MountPoint)" -Data $bitlockerInfo -Icon $CardIcon -BackgroundGradient $CardBackgroundGradient -BorderRadius $CardBorderRadius -IconColor $CardIconColor -SeparationMargin $CardSeparationMargin
        $allCardsHtml += $cardHtml
    }
    
    # Store all cards in the custom field
    try {
        $allCardsHtml | Ninja-Property-Set-Piped -Name $BitLockerStatusFieldName
        Write-Log "SUCCESS" "BitLocker status cards stored in '$BitLockerStatusFieldName'"
    }
    catch {
        Write-Log "ERROR" "Failed to store status cards: $_"
    }
    
    # Store recovery keys in a single-line format if override is enabled
    if ($UpdateRecoveryKeys) {
        Write-Log "INFO" "Storing all collected recovery keys in secure field"
        try {
            if ($script:RecoveryKeys.Count -eq 0) {
                Write-Log "INFO" "No recovery keys collected; setting secure field to N/A"
                Ninja-Property-Set $RecoveryKeySecureFieldName "N/A" | Out-Null
            }
            else {
                $allKeys = ($script:RecoveryKeys.Values -join "; ")
                Ninja-Property-Set $RecoveryKeySecureFieldName $allKeys | Out-Null
                Write-Log "SUCCESS" "Stored recovery keys for drive(s) ($($script:RecoveryKeys.Keys -join ', ')) in '$RecoveryKeySecureFieldName'"
                # Clear sensitive data
                Clear-Memory -VariableNames "allKeys"
            }
        }
        catch {
            Write-Log "ERROR" "Failed to store recovery keys: $_"
        }
    }

    # Clear sensitive state
    Clear-Memory -VariableNames "RecoveryKeys"
    
    Write-Host "`n=== Complete ==="
    Write-Log "SUCCESS" "BitLocker status reporting completed"
}

#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieve Bitlocker information and update NinjaRMM custom fields.

.DESCRIPTION
    This script retrieves key Bitlocker details for a specified mount point, including protection status, 
    encryption method, current protectors, and recovery key, then updates NinjaRMM custom fields.
    Optionally, it can update the recovery key in a secure field if the updateRecoveryKey flag is enabled.
    It is designed to run on a schedule for monitoriStore-RecoveryKeyng purposes, using environment variables as a fallback for configuration.

.PARAMETER MountPoint
    The drive letter or mount point to check (e.g., 'C:'). Defaults to the system drive or env:bitlockerMountPoint if set.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to C:\Logs\BitLockerInfo.log on the device.
#>

[CmdletBinding()]
param(
    # Drive letter or mount point, with fallback to environment variable or system drive
    [string]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint } else { (Get-CimInstance Win32_OperatingSystem).SystemDrive }),

    # New parameter to control recovery key update
    [switch]$UpdateRecoveryKey = $(if ($env:updateRecoveryKey) { [Convert]::ToBoolean($env:updateRecoveryKey) } else { $false }),
    # Switch to enable logging to a file on the device
    [switch]$SaveLogToDevice = $(if ($env:saveLogToDevice) { [Convert]::ToBoolean($env:saveLogToDevice) } else { $false }),

    # Custom feild names for storing info
    [string]$MountPointFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerMountPoint" }),
    [string]$ProtectionStateFieldName = $(if ($env:protectionStateFieldName) { $env:protectionStateFieldName } else { "BitLockerProtectionState" }),
    [string]$EncryptionMethodFieldName = $(if ($env:encryptionMethodFieldName) { $env:encryptionMethodFieldName } else { "BitLockerEncryptionMethod" }),
    [string]$UsedSpaceOnlyFieldName = $(if ($env:usedSpaceOnlyFieldName) { $env:usedSpaceOnlyFieldName } else { "BitLockerUsedSpaceOnly" }),
    [string]$CurrentProtectorsFieldName = $(if ($env:currentProtectorsFieldName) { $env:currentProtectorsFieldName } else { "BitLockerCurrentProtectors" }),
    [string]$RecoveryKeySecureFieldName = $(if ($env:recoveryKeySecureFieldName) { $env:recoveryKeySecureFieldName } else { "BitLockerRecoveryKey" })
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

    # Helper function: Store mount point in NinjaRMM custom field
    function Store-MountPoint {
        param($mountPoint)
        Write-Host "`n=== Section: Store Bitlocker Volume ==="
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
        Write-Host "`n=== Section: Store Protection State ==="
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
        Write-Host "`n=== Section: Store Encryption Method ==="
        try {
            Ninja-Property-Set $EncryptionMethodFieldName $encryptionMethod | Out-Null
            Write-Log "SUCCESS" "Encryption method stored in custom field '$EncryptionMethodFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store encryption method: $_"
        }
    }

    # Helper function: Store current protectors in NinjaRMM custom field
    function Store-CurrentProtectors {
        param($volume)
        Write-Host "`n=== Section: Store Protectors ==="
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

        Write-Host "`n=== Section: Protection Detection ==="
        # Update custom fields based on current state
        if ($script:blv.ProtectionStatus -eq 'Off' -and $script:blv.VolumeStatus -eq 'FullyDecrypted') {

            Write-Log "INFO" "Bitlocker is fully disabled on $MountPoint"
            # Set fields to "N/A" when Bitlocker is fully disabled, matching full script logic
            Store-MountPoint -mountPoint "N/A"
            Store-ProtectionState -protectionState "N/A"
            Store-EncryptionMethod -encryptionMethod "N/A"
            # UsedSpaceOnly cannot be retrieved except during encryption/decryption
        }
        else {
            Write-Log "INFO" "Bitlocker is enabled on $MountPoint"
            # Store actual values for active or partially active volumes
            Store-MountPoint -mountPoint $MountPoint
            Store-ProtectionState -protectionState $script:blv.ProtectionStatus
            if ($script:blv.VolumeStatus -eq 'FullyEncrypted' -or $script:blv.VolumeStatus -eq 'EncryptionInProgress') {
                Store-EncryptionMethod -encryptionMethod $script:blv.EncryptionMethod
            }
            else {
                Store-EncryptionMethod -encryptionMethod "N/A"
            }
            # UsedSpaceOnly cannot be retrieved except during encryption/decryption
        }
        
        # Always store current protectors and recovery key
        Store-CurrentProtectors -volume $script:blv

    }
    catch {
        Write-Log "ERROR" "Failed to retrieve Bitlocker volume for ${MountPoint}: $_"
        exit 1
    }
}

# =========================================
# END Block: Finalization
# =========================================
end {
    Write-Log "INFO" "Bitlocker information retrieval and custom field updates completed"
}
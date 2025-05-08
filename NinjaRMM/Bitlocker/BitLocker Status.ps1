#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieve BitLocker information and update NinjaRMM custom fields.

.DESCRIPTION
    This script retrieves key BitLocker details for a specified mount point, including protection status, 
    encryption method, current protectors, and recovery key, then updates NinjaRMM custom fields using 
    the same storage logic as the full management script. It is designed to run on a schedule for 
    monitoring purposes, using environment variables as a fallback for configuration.

.PARAMETER MountPoint
    The drive letter or mount point to check (e.g., 'C:'). Defaults to the system drive or env:bitlockerMountPoint if set.

.PARAMETER SaveLogToDevice
    If specified, logs are saved to C:\Logs\BitLockerInfo.log on the device.
#>

[CmdletBinding()]
param(
    # Drive letter or mount point, with fallback to environment variable or system drive
    [string]$MountPoint = $(if ($env:bitlockerMountPoint) { $env:bitlockerMountPoint } else { (Get-CimInstance Win32_OperatingSystem).SystemDrive }),
    # Switch to enable logging to a file on the device
    [switch]$SaveLogToDevice = [Convert]::ToBoolean($env:saveLogToDevice)
)

# =========================================
# BEGIN Block: Initialization & Validation
# =========================================
begin {
    # Custom field names for NinjaRMM, with fallbacks to environment variables if set
    # Environment variables can be used to override default custom field names:
    #   $env:bitlockerMountPointField
    #   $env:bitlockerProtectionStateField
    #   $env:bitlockerEncryptionMethodField
    #   $env:bitlockerCurrentProtectorsField
    #   $env:bitlockerRecoveryKeyField
    
    $MountPointFieldName = if ($env:bitlockerVolumeCustomField) { $env:bitlockerVolumeCustomField } else { "BitLockerMountPoint" }
    $ProtectionStateFieldName = if ($env:bitlockerProtectionStateCustomField) { $env:bitlockerProtectionStateCustomField } else { "BitLockerProtectionState" }
    $EncryptionMethodFieldName = if ($env:bitlockerEncryptionMethodCustomField) { $env:bitlockerEncryptionMethodCustomField } else { "BitLockerEncryptionMethod" }
    $CurrentProtectorsFieldName = if ($env:bitlockerCurrentProtectorsCustomField) { $env:bitlockerCurrentProtectorsCustomField } else { "BitLockerCurrentProtectors" }
    $RecoveryKeySecureFieldName = if ($env:bitlockerRecoveryKeySecureCustomField) { $env:bitlockerRecoveryKeySecureCustomField } else { "BitLockerRecoveryKey" }
    # UsedSpaceOnly cannot be retrieved post-encryption. Cannot include UsedSpaceOnly.

    # Verify administrator privileges
    $isAdmin = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Administrator privileges required"
        exit 1
    }

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

    # Helper function: Refresh drive state
    function Get-VolumeObject {
        try {
            # Sublogic: Retrieve BitLocker volume object and suppress all non-error output
            $script:blv = Get-BitLockerVolume `
                -MountPoint $MountPoint `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue
            Write-Log "SUCCESS" "Volume state refreshed: ProtectionStatus=$($script:blv.ProtectionStatus), VolumeStatus=$($script:blv.VolumeStatus)"
        }
        catch {
            Write-Log "ERROR" "No BitLocker volume at ${MountPoint}: $_"
            throw
        }
    }

    # Helper function: Return the list of valid recovery protectors
    function Get-ValidRecoveryProtectors {
        param($volume)
        Write-Host "`n=== Section: Store Protectors ==="
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
                Write-Log "INFO" "Found valid recovery key protector"
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

<#  
    # Helper function: Store used space only flag in NinjaRMM custom field
    UsedSpaceOnly cannot be retrieved post-encryption
    function Store-UsedSpaceOnly {
        param($usedSpaceOnly)
        Write-Host "`n=== Section: Store Used Space Only (for encryption) ==="
        try {
            $valueToStore = if ($usedSpaceOnly -is [bool]) { $usedSpaceOnly.ToString() } else { $usedSpaceOnly }
            Ninja-Property-Set $UsedSpaceOnlyFieldName $valueToStore | Out-Null
            Write-Log "SUCCESS" "Used space only flag stored in custom field '$UsedSpaceOnlyFieldName'"
        }
        catch {
            Write-Log "ERROR" "Failed to store used space only flag: $_"
        }
    }
#>

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

    # Helper function: Store recovery key in NinjaRMM secure field
    function Store-RecoveryKey {
        param($volume)
        Write-Host "`n=== Section: Store Recovery Key ==="
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
        
        # Retry loop to detect the recovery key
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
        
        # Store the latest key if available
        if ($protectors) {
            $latestProtector = $protectors | Sort-Object { $_.KeyProtectorId } | Select-Object -Last 1
            $keyInfo = "ID: $($latestProtector.KeyProtectorId)`nKey: $($latestProtector.RecoveryPassword)"
            Write-Log "INFO" "Storing recovery key: $($latestProtector.KeyProtectorId)"
            try {
                Ninja-Property-Set $RecoveryKeySecureFieldName $keyInfo | Out-Null
                Write-Log "SUCCESS" "Recovery key stored in secure field '$RecoveryKeySecureFieldName'"
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

    Write-Log "INFO" "Starting BitLocker information retrieval for mount point: $MountPoint"
}

# =========================================
# PROCESS Block: Retrieve and Store BitLocker Information
# =========================================
process {
    try {
        # Retrieve the BitLocker volume
        Write-Host "`n=== Section: Volume Status ==="
        Get-VolumeObject

        Write-Host "`n=== Section: Protection Detection ==="
        # Update custom fields based on current state
        if ($script:blv.ProtectionStatus -eq 'Off' -and $script:blv.VolumeStatus -eq 'FullyDecrypted') {

            Write-Log "INFO" "BitLocker is fully disabled on $MountPoint"
            # Set fields to "N/A" when BitLocker is fully disabled, matching full script logic
            Store-MountPoint -mountPoint "N/A"
            Store-ProtectionState -protectionState "N/A"
            Store-EncryptionMethod -encryptionMethod "N/A"
            # UsedSpaceOnly cannot be retrieved except during encryption/decryption
        }
        else {
            Write-Log "INFO" "BitLocker is enabled on $MountPoint"
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
        Store-RecoveryKey -volume $script:blv
    }
    catch {
        Write-Log "ERROR" "Failed to retrieve BitLocker volume for ${MountPoint}: $_"
        # Set fields to indicate an error occurred
        Store-MountPoint -mountPoint $MountPoint
        Store-ProtectionState -protectionState "Error"
        Store-EncryptionMethod -encryptionMethod "Error"
        # UsedSpaceOnly cannot be retrieved except during encryption/decryption
        Store-CurrentProtectors -volume $script:blv
        Store-RecoveryKey -volume $script:blv
    }
}

# =========================================
# END Block: Finalization
# =========================================
end {
    Write-Log "INFO" "BitLocker information retrieval completed"
}
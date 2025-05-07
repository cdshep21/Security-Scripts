<# PowerShell Script 1: Securely Handling API Keys #>
 
# Function to encrypt access and secret keys
Function Encrypt-Keys {
    param (
        [string]$AccessKey,
        [string]$SecretKey
    )
 
    # Decode the key from Base64 and validate its length
    $fernetKey = [Convert]::FromBase64String($Env:FERNET)
    if ($fernetKey.Length -ne 32) {
        Write-Output "Encryption key validation failed: Decoded key size: $($fernetKey.Length) bytes. The key must be exactly 32 bytes (256 bits)."
    }
 
    # Use AES for encryption
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $fernetKey
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $iv = $aes.IV
 
    # Combine the keys and encrypt them
    $encryptor = $aes.CreateEncryptor()
    $combinedKey = "${AccessKey};${SecretKey}"
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($combinedKey)
    $ciphertext = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)
 
    # Combine the IV and ciphertext
    $encryptedData = [Convert]::ToBase64String($iv + $ciphertext)
    return $encryptedData
}
 
# Function to create or update the JSON configuration file
Function Create-ConfigFile {
    param (
        [string]$FileName = "config.json",
        [hashtable]$ConfigData
    )
 
    if (Test-Path $FileName) {
        Write-Output "$FileName already exists. Merging new entries with the existing configuration."
        $existingData = Get-Content $FileName | ConvertFrom-Json
        $existingHashtable = @{}
        foreach ($property in $existingData.PSObject.Properties) {
            $existingHashtable[$property.Name] = $property.Value
        }
        foreach ($key in $ConfigData.Keys) {
            $existingHashtable[$key] = $ConfigData[$key]
        }
        $existingHashtable | ConvertTo-Json -Depth 10 | Set-Content -Path $FileName -Force
    } else {
        $ConfigData | ConvertTo-Json -Depth 10 | Set-Content -Path $FileName -Force
    }
    Write-Output "Configuration saved to $FileName"
}
 
# Main script logic
Function Main {
    $configFile = "config.json"
 
    if ($Env:FERNET) {
        Write-Output "Choose an option:"
        Write-Output "1. Add more Security Centers to the existing configuration."
        Write-Output "2. Wipe the existing configuration file."
 
        $option = Read-Host "Enter the number corresponding to your choice (1 or 2)"
 
        switch ($option) {
            "1" {
                Write-Output "Adding to the existing configuration."
            }
            "2" {
                $confirm = Read-Host "Are you sure you want to wipe the key and configuration file? This action cannot be undone. (yes/no)"
                if ($confirm -eq "yes") {
                    Remove-Item -Path $configFile -ErrorAction SilentlyContinue
                    [Environment]::SetEnvironmentVariable("FERNET", $null, [EnvironmentVariableTarget]::User)
                    Write-Output "Existing config file and FERNET key deleted. Starting fresh."
                    Write-Output "Run generate_key.ps1 to create encryption key"
                } else {
                    Write-Output "Operation canceled."
                    return
                }
            }
            default {
                Write-Output "Invalid choice. Exiting script."
                return
            }
        }
    } else {
        Write-Output "Run generate_key.ps1 to create encryption key"
    }
 
    $securityCenters = @{}
 
    while ($true) {
        $centerName = Read-Host "Enter a name for the Security Center (e.g., acas1)"
        if (-not $centerName) {
            Write-Output "Security Center name cannot be empty."
            continue
        }
 
        $url = Read-Host "Enter the URL for $centerName"
        $accessKey = Read-Host "Enter the Access Key for $centerName"
        $secretKey = Read-Host "Enter the Secret Key for $centerName"
 
        $encryptedKey = Encrypt-Keys -AccessKey $accessKey -SecretKey $secretKey
 
        $securityCenters[$centerName] = @{
            url = $url
            encrypted_key = $encryptedKey
        }
 
        $more = Read-Host "Do you want to add another Security Center? (yes/no)"
        if ($more -ne "yes") {
            break
        }
    }
 
    Create-ConfigFile -ConfigData $securityCenters
}
 
Main
 
<#
PowerShell Script: Query and Download Reports with Logging
#>
 
# Configuration
$Config = @{
    MaxRetries = 3
    RetryDelay = 5
    TimeoutSeconds = 30
    BatchSize = 10
    LogLevel = "INFO"  # DEBUG, INFO, WARNING, ERROR
}

# Logging function
Function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "DEBUG" { if ($Config.LogLevel -in @("DEBUG")) { Write-Host $logMessage -ForegroundColor Gray } }
        "INFO" { if ($Config.LogLevel -in @("DEBUG", "INFO")) { Write-Host $logMessage -ForegroundColor White } }
        "WARNING" { if ($Config.LogLevel -in @("DEBUG", "INFO", "WARNING")) { Write-Host $logMessage -ForegroundColor Yellow } }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    Add-Content -Path $script:LogFile -Value $logMessage
}

# Function to validate and sanitize input
Function Test-Input {
    param(
        [string]$Input,
        [string]$Type
    )
    switch ($Type) {
        "Date" {
            try {
                $date = [DateTime]::ParseExact($Input, "yyyy-MM-dd HH:mm", $null)
                return $true
            } catch {
                Write-Log "Invalid date format. Expected: YYYY-MM-DD HH:MM" -Level "ERROR"
                return $false
            }
        }
        "Url" {
            try {
                $uri = [System.Uri]$Input
                return $uri.Scheme -in @("http", "https")
            } catch {
                Write-Log "Invalid URL format" -Level "ERROR"
                return $false
            }
        }
        "FileName" {
            return $Input -match '^[^<>:"/\\|?*]+$'
        }
    }
}

# Function to load the encryption key from the environment variable
Function Load-FernetKey {
    if (-not $Env:FERNET) {
        Write-Log "FERNET environment variable is not set." -Level "ERROR"
        throw "FERNET environment variable is not set."
    }
    try {
        $key = [Convert]::FromBase64String($Env:FERNET)
        if ($key.Length -ne 32) {
            throw "Invalid key length"
        }
        return $key
    } catch {
        Write-Log "Failed to load encryption key: $_" -Level "ERROR"
        throw
    }
}

# Function to decrypt the encrypted access and secret keys
Function Decrypt-Key {
    param (
        [string]$EncryptedKey
    )
    try {
        $fernetKey = Load-FernetKey
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $fernetKey
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $encryptedData = [Convert]::FromBase64String($EncryptedKey)
        $iv = $encryptedData[0..15]
        $ciphertext = $encryptedData[16..($encryptedData.Length - 1)]
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $plaintextBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        return [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
    } catch {
        Write-Log "Failed to decrypt key: $_" -Level "ERROR"
        throw
    }
}

# Function to load the configuration file
Function Load-ConfigFile {
    param (
        [string]$ConfigPath = "config.json"
    )
    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Configuration file not found: $ConfigPath" -Level "ERROR"
        throw "Configuration file not found: $ConfigPath"
    }
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        foreach ($center in $config.PSObject.Properties) {
            if (-not (Test-Input -Input $center.Value.url -Type "Url")) {
                throw "Invalid URL in configuration for $($center.Name)"
            }
        }
        return $config
    } catch {
        Write-Log "Failed to load configuration: $_" -Level "ERROR"
        throw
    }
}

# Function to query Tenable using Invoke-RestMethod
Function Query-Tenable {
    param (
        [string]$TenableUrl,
        [string]$ApiKey,
        [int]$StartEpoch,
        [int]$EndEpoch
    )
    $retryCount = 0
    while ($retryCount -lt $Config.MaxRetries) {
        try {
            $headers = @{
                "x-apikey" = $ApiKey
                "Content-Type" = "application/json"
            }
            
            $response = Invoke-RestMethod -Uri "$TenableUrl/rest/report?fields=id,name,type,finishTime" `
                                        -Headers $headers `
                                        -Method Get `
                                        -TimeoutSec $Config.TimeoutSeconds `
                                        -ErrorAction Stop

            $reports = $response.response.usable
            $filteredReports = $reports | Where-Object {
                $_.type -in @("pdf", "csv") -and 
                $_.finishTime -and 
                ($_.finishTime -as [int]) -ge $StartEpoch -and 
                ($_.finishTime -as [int]) -le $EndEpoch
            }
            return $filteredReports
        } catch {
            $retryCount++
            if ($retryCount -eq $Config.MaxRetries) {
                Write-Log "Failed to query Tenable after $($Config.MaxRetries) attempts: $_" -Level "ERROR"
                throw
            }
            Write-Log "Query attempt $retryCount failed. Retrying in $($Config.RetryDelay) seconds..." -Level "WARNING"
            Start-Sleep -Seconds $Config.RetryDelay
        }
    }
}

# Function to sanitize file names
Function Sanitize-FileName {
    param ([string]$FileName)
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $sanitized = $FileName
    foreach ($char in $invalidChars) {
        $sanitized = $sanitized.Replace($char, '_')
    }
    return $sanitized
}

# Function to download a report using Invoke-RestMethod
Function Download-Report {
    param (
        [Object]$Report,
        [string]$TenableUrl,
        [string]$ApiKey,
        [string]$ReportsFolder
    )
    $reportId = $Report.id
    $reportName = Sanitize-FileName -FileName $Report.name
    $fileType = $Report.type.ToLower()
    $reportPath = Join-Path $ReportsFolder "$reportName.$fileType"
    
    $retryCount = 0
    while ($retryCount -lt $Config.MaxRetries) {
        try {
            $headers = @{
                "x-apikey" = $ApiKey
                "Content-Type" = "application/json"
            }
            
            $response = Invoke-RestMethod -Uri "$TenableUrl/rest/report/$reportId/download" `
                                        -Headers $headers `
                                        -Method Post `
                                        -TimeoutSec $Config.TimeoutSeconds `
                                        -OutFile $reportPath `
                                        -ErrorAction Stop

            # Verify file was downloaded
            if (Test-Path $reportPath) {
                $fileInfo = Get-Item $reportPath
                if ($fileInfo.Length -gt 0) {
                    Write-Log "Successfully downloaded report: $reportName.$fileType" -Level "INFO"
                    return $true
                }
            }
            throw "File download verification failed"
        } catch {
            $retryCount++
            if ($retryCount -eq $Config.MaxRetries) {
                Write-Log "Failed to download report after $($Config.MaxRetries) attempts: $_" -Level "ERROR"
                return $false
            }
            Write-Log "Download attempt $retryCount failed. Retrying in $($Config.RetryDelay) seconds..." -Level "WARNING"
            Start-Sleep -Seconds $Config.RetryDelay
        }
    }
    return $false
}

# Main script logic
Function Main {
    $outputFolderName = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_Tenable-Reports"
    $outputFolder = Join-Path (Get-Location) $outputFolderName
    $reportsFolder = Join-Path $outputFolder "reports"
    $script:LogFile = Join-Path $outputFolder "$outputFolderName.log"

    try {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
        New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null

        Write-Log "Starting Tenable Reports download process" -Level "INFO"
        
        $fernetKey = Load-FernetKey
        $config = Load-ConfigFile

        do {
            $startDate = Read-Host "Enter the start date (YYYY-MM-DD HH:MM)"
        } while (-not (Test-Input -Input $startDate -Type "Date"))

        do {
            $endDate = Read-Host "Enter the end date (YYYY-MM-DD HH:MM)"
        } while (-not (Test-Input -Input $endDate -Type "Date"))

        $startEpoch = [DateTimeOffset]::ParseExact($startDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()
        $endEpoch = [DateTimeOffset]::ParseExact($endDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()

        foreach ($centerName in $config.PSObject.Properties.Name) {
            Write-Log "Processing Security Center: $centerName" -Level "INFO"
            
            $centerInfo = $config.$centerName
            $tenableUrl = $centerInfo.url
            $encryptedKey = $centerInfo.encrypted_key
            
            try {
                $decryptedKey = Decrypt-Key -EncryptedKey $encryptedKey
                $keys = $decryptedKey -split ";"
                $apiKey = "accesskey=$($keys[0]); secretkey=$($keys[1])"

                $reportList = Query-Tenable -TenableUrl $tenableUrl -ApiKey $apiKey -StartEpoch $startEpoch -EndEpoch $endEpoch

                if ($reportList) {
                    $successCount = 0
                    $failCount = 0
                    
                    foreach ($report in $reportList) {
                        if (Download-Report -Report $report -TenableUrl $tenableUrl -ApiKey $apiKey -ReportsFolder $reportsFolder) {
                            $successCount++
                        } else {
                            $failCount++
                        }
                    }
                    
                    Write-Log "Completed processing $centerName. Success: $successCount, Failed: $failCount" -Level "INFO"
                } else {
                    Write-Log "No reports found for Security Center: $centerName" -Level "WARNING"
                }
            } catch {
                Write-Log "Error processing $centerName: $_" -Level "ERROR"
                continue
            }
        }
    } catch {
        Write-Log "Fatal error: $_" -Level "ERROR"
    } finally {
        Write-Log "Script execution completed" -Level "INFO"
    }
}

Main
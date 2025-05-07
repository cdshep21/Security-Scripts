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
 
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
 
# Function to load the encryption key from the environment variable
Function Load-FernetKey {
    if (-not $Env:FERNET) {
        throw "FERNET environment variable is not set."
    }
    return [Convert]::FromBase64String($Env:FERNET)
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
        throw "Failed to decrypt key: $_"
    }
}
 
# Function to load the configuration file
Function Load-ConfigFile {
    param (
        [string]$ConfigPath = "config.json"
    )
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }
    return Get-Content $ConfigPath | ConvertFrom-Json
}
 
# Function to query Tenable using curl
Function Query-Tenable {
    param (
        [string]$TenableUrl,
        [string]$ApiKey,
        [int]$StartEpoch,
        [int]$EndEpoch
    )
    $curlCommand = @(
        "curl.exe",
        "-k",
        "-X GET",
        "`"$TenableUrl/rest/report?fields=id,name,type,finishTime`"",
        "-H `"x-apikey: $ApiKey`"",
        "-H `"Content-Type: application/json`""
    ) -join " "
 
#    Write-Host "Executing: $curlCommand"
    $response = & cmd /c $curlCommand
 
    try {
        $jsonResponse = $response | ConvertFrom-Json
        $reports = $jsonResponse.response.usable
        $filteredReports = $reports | Where-Object {
            $_.type -in @("pdf", "csv") -and $_.finishTime -and ($_.finishTime -as [int]) -ge $StartEpoch -and ($_.finishTime -as [int]) -le $EndEpoch
        }
        return $filteredReports
    } catch {
        Write-Host "Error parsing response: $_"
        return @()
    }
}
 
# Function to sanitize file names
Function Sanitize-FileName {
    param ([string]$FileName)
    return $FileName -replace '[<>:"/\\|?*]', '_'
}
 
# Function to download a report using curl
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
 
    $curlCommand = @(
        "curl.exe -k -X POST",
        "`"$TenableUrl/rest/report/$reportId/download`"",
        "-H `"x-apikey: $ApiKey`"",
        "-H `"Content-Type: application/json`"",
        "-o `"$reportPath`""
    ) -join " "
#    Write-Host "Executing: $curlCommand"
& cmd /c $curlCommand
    Write-Output "Downloaded report: $reportName.$fileType"
}
 
# Main script logic
Function Main {
    $outputFolderName = (Get-Date -Format "yyyy-MM-dd_HH-mm") + "_Tenable-Reports"
    $outputFolder = Join-Path (Get-Location) $outputFolderName
    $reportsFolder = Join-Path $outputFolder "reports"
    $logFile = Join-Path $outputFolder "$outputFolderName.log"
 
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    New-Item -ItemType Directory -Path $reportsFolder -Force | Out-Null
 
    Start-Transcript -Path $logFile -Append
 
    try {
        $fernetKey = Load-FernetKey
        $config = Load-ConfigFile
        $startDate = Read-Host "Enter the start date (YYYY-MM-DD HH:MM)"
        $endDate = Read-Host "Enter the end date (YYYY-MM-DD HH:MM)"
        $startEpoch = [DateTimeOffset]::ParseExact($startDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()
        $endEpoch = [DateTimeOffset]::ParseExact($endDate, "yyyy-MM-dd HH:mm", $null).ToUnixTimeSeconds()
 
        foreach ($centerName in $config.PSObject.Properties.Name) {
            $centerInfo = $config.$centerName
            $tenableUrl = $centerInfo.url
            $encryptedKey = $centerInfo.encrypted_key
            $decryptedKey = Decrypt-Key -EncryptedKey $encryptedKey
            $keys = $decryptedKey -split ";"
            $apiKey = "accesskey=$($keys[0]); secretkey=$($keys[1])"
 
            Write-Output "Querying Security Center: $centerName"
            $reportList = Query-Tenable -TenableUrl $tenableUrl -ApiKey $apiKey -StartEpoch $startEpoch -EndEpoch $endEpoch
 
            if ($reportList) {
                foreach ($report in $reportList) {
                    Download-Report -Report $report -TenableUrl $tenableUrl -ApiKey $apiKey -ReportsFolder $reportsFolder
                }
            } else {
                Write-Output "No reports found for Security Center: $centerName"
            }
        }
    } catch {
        Write-Output "Error: $_"
    } finally {
        Stop-Transcript
    }
}
 
Main
 

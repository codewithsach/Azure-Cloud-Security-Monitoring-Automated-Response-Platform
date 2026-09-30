Sentinel Training Lab - Data Ingestion Script
=======================================================================
 Loads the official pre-recorded Sentinel training telemetry into your
 Log Analytics workspace using the HTTP Data Collector API.

 Why this script exists: the one-click "Sentinel Training Lab" content
 hub item that used to load this same data was removed from Microsoft's
 content hub during this build (confirmed against a public issue filed
 on the Azure/Azure-Sentinel GitHub repo). This script loads the exact
 same underlying CSVs directly, which is arguably closer to how a real
 ingestion pipeline works than a one-click sample anyway.

 Data lands in these custom tables (Azure adds the _CL suffix):
    SecurityEvent_CL, SigninLogs_CL, OfficeActivity_CL, AzureActivity_CL

 USAGE (run from Azure Cloud Shell - it authenticates automatically,
 which avoids identity/tenant issues you can hit running this locally):

    ./ingest-training-lab-data.ps1 `
        -WorkspaceId  "<your-workspace-id>" `
        -WorkspaceKey "<your-primary-key>"

 Find these values in your workspace: Settings > Agents > Workspace ID
 and Primary key.

 Data usually takes 10-15 minutes to appear the first time.
=======================================================================
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceKey
)

# ---- Helper: build the authorization signature ----------------------
function Build-Signature {
    param($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)

    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    return 'SharedKey {0}:{1}' -f $customerId, $encodedHash
}

# ---- Helper: post one CSV file to a Log Analytics table --------------
function Send-ToLogAnalytics {
    param($url, $EventsTable, $customerId, $sharedKey)

    Write-Host "Downloading: $url"
    $data = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
    $records = ConvertFrom-Csv $data
    $json = $records | ConvertTo-Json -Depth 3
    $body = [Text.Encoding]::UTF8.GetBytes($json)

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature $customerId $sharedKey $rfc1123date $contentLength $method $contentType $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature
        "Log-Type"             = $EventsTable
        "x-ms-date"            = $rfc1123date
        "time-generated-field" = ""
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    Write-Host "  -> $EventsTable : HTTP $($response.StatusCode)  ($($records.Count) records)"
}

# ---- The four official Training Lab telemetry files -----------------
$base = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Solutions/Training/Azure-Sentinel-Training-Lab/Artifacts/Telemetry"

Write-Host "`n=== Starting Sentinel Training Lab data ingestion ===`n"

Send-ToLogAnalytics -url "$base/securityEvents.csv"             -EventsTable "SecurityEvent"  -customerId $WorkspaceId -sharedKey $WorkspaceKey
Send-ToLogAnalytics -url "$base/disable_accounts.csv"           -EventsTable "SigninLogs"     -customerId $WorkspaceId -sharedKey $WorkspaceKey
Send-ToLogAnalytics -url "$base/office_activity_inbox_rule.csv" -EventsTable "OfficeActivity" -customerId $WorkspaceId -sharedKey $WorkspaceKey
Send-ToLogAnalytics -url "$base/azureActivity_adele.csv"        -EventsTable "AzureActivity"  -customerId $WorkspaceId -sharedKey $WorkspaceKey

Write-Host "`n=== Done. Data will appear in *_CL tables in ~10-15 minutes. ==="
Write-Host "Verify with:  SecurityEvent_CL | take 10`n"

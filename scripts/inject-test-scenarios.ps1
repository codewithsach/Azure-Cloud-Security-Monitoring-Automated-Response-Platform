<#
=======================================================================
 Test Scenario Injector - Impossible Travel & Privilege Escalation
=======================================================================
 Two of the six detection rules (impossible travel, privilege
 escalation) need an event the base training lab dataset doesn't
 naturally contain. This script injects a controlled test event for
 either scenario so you can validate the rule fires correctly.

 This is disclosed openly in the project report: the detection logic
 is real and general-purpose, the test data point is constructed
 because a small lab environment doesn't produce it organically.

 USAGE:
    ./inject-test-scenarios.ps1 -WorkspaceId "<id>" -WorkspaceKey "<key>" -Scenario ImpossibleTravel
    ./inject-test-scenarios.ps1 -WorkspaceId "<id>" -WorkspaceKey "<key>" -Scenario PrivilegeEscalation

 Data usually takes 10-15 minutes to appear. Query with a "Last 1 hour"
 time range afterward.
=======================================================================
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceKey,

    [Parameter(Mandatory = $true)]
    [ValidateSet("ImpossibleTravel", "PrivilegeEscalation")]
    [string]$Scenario,

    # Optional - override the identity used in the test event.
    # Defaults are safe placeholders, not real accounts.
    [string]$TestUserPrincipalName = "johns@m365x816222.onmicrosoft.com",
    [string]$CallerUpn = "admin@yourtenant.onmicrosoft.com"
)

function Send-Event {
    param($records, $logType, $customerId, $sharedKey)

    $json = ConvertTo-Json $records
    $body = [Text.Encoding]::UTF8.GetBytes($json)

    $method = "POST"; $contentType = "application/json"; $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $xHeaders = "x-ms-date:" + $rfc1123date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    # NOTE: deliberately no "time-generated-field" header. Including a
    # custom header here silently dropped injected rows during testing -
    # letting Log Analytics assign ingestion time fixed it.
    $headers = @{ "Authorization" = $authorization; "Log-Type" = $logType; "x-ms-date" = $rfc1123date }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

if ($Scenario -eq "ImpossibleTravel") {
    # Same user, two sign-ins minutes apart, two distant countries.
    $now = [DateTime]::UtcNow
    $records = @(
        @{
            TimeGenerated     = $now.ToString("o")
            ResultType        = 50057
            ResultDescription = "User account is disabled"
            Identity          = "TestUser"
            UserPrincipalName = $TestUserPrincipalName
            UserDisplayName   = "TestUser"
            IPAddress         = "175.45.176.99"
            Location          = "KP"
            AppDisplayName    = "Azure Portal"
            ClientAppUsed     = "Browser"
            OperationName     = "Sign-in activity"
            Category          = "SignInLogs"
        },
        @{
            TimeGenerated     = $now.AddMinutes(3).ToString("o")
            ResultType        = 0
            ResultDescription = "Successful sign-in"
            Identity          = "TestUser"
            UserPrincipalName = $TestUserPrincipalName
            UserDisplayName   = "TestUser"
            IPAddress         = "13.107.42.14"
            Location          = "US"
            AppDisplayName    = "Azure Portal"
            ClientAppUsed     = "Browser"
            OperationName     = "Sign-in activity"
            Category          = "SignInLogs"
        }
    )
    $status = Send-Event -records $records -logType "SigninLogs" -customerId $WorkspaceId -sharedKey $WorkspaceKey
    Write-Host "Injected impossible-travel scenario (KP + US) for $TestUserPrincipalName -> HTTP $status"
}
elseif ($Scenario -eq "PrivilegeEscalation") {
    $now = [DateTime]::UtcNow
    $records = @(
        @{
            TimeGenerated         = $now.ToString("o")
            OperationNameValue    = "Microsoft.Authorization/roleAssignments/write"
            OperationName         = "Create role assignment"
            Caller                = $CallerUpn
            CallerIPAddress       = "203.0.113.55"   # RFC 5737 documentation range - not a real IP
            ActivityStatusValue   = "Success"
            ResourceGroup         = "rg-capstone-soc"
            ResourceProviderValue = "MICROSOFT.AUTHORIZATION"
            CategoryValue         = "Administrative"
            Level                 = "Informational"
        }
    )
    $status = Send-Event -records $records -logType "AzureActivity" -customerId $WorkspaceId -sharedKey $WorkspaceKey
    Write-Host "Injected privilege-escalation scenario for $CallerUpn -> HTTP $status"
}

Write-Host "Wait ~10-15 minutes, then re-run the matching detection rule against a 'Last 1 hour' window."

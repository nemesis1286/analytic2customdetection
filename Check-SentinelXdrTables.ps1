<#
.SYNOPSIS
    Checks Microsoft Sentinel analytic rules for usage of Defender XDR
    advanced hunting tables and generates a report.

.DESCRIPTION
    This script connects to a Microsoft Sentinel workspace, retrieves all
    analytic rules (Scheduled and NRT), parses their KQL queries for
    references to Defender XDR tables, and outputs a detailed report.

    The report includes:
    - Rule display name, severity, and enabled status
    - Which XDR tables each rule references
    - The product area each table belongs to
    - Summary statistics

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name used by Sentinel.

.PARAMETER OutputFormat
    Output format for the report: Console, CSV, or JSON. Default is Console.

.PARAMETER OutputPath
    File path for CSV or JSON output. If not specified, a default filename
    is generated in the current directory.

.PARAMETER IncludeDisabled
    Include disabled analytic rules in the scan. By default, only enabled
    rules are checked.

.EXAMPLE
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel"

.EXAMPLE
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -OutputFormat CSV -OutputPath ".\report.csv"

.EXAMPLE
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -IncludeDisabled -OutputFormat JSON
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "JSON")]
    [string]$OutputFormat = "Console",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Defender XDR advanced hunting table registry
# ---------------------------------------------------------------------------
# Organised by product area. This list aligns with the official Microsoft
# Defender XDR advanced hunting schema.
# Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables

$XdrTableRegistry = @{
    # Microsoft Defender for Endpoint
    "DeviceEvents"                              = "Microsoft Defender for Endpoint"
    "DeviceFileEvents"                          = "Microsoft Defender for Endpoint"
    "DeviceFileCertificateInfo"                 = "Microsoft Defender for Endpoint"
    "DeviceImageLoadEvents"                     = "Microsoft Defender for Endpoint"
    "DeviceInfo"                                = "Microsoft Defender for Endpoint"
    "DeviceLogonEvents"                         = "Microsoft Defender for Endpoint"
    "DeviceNetworkEvents"                       = "Microsoft Defender for Endpoint"
    "DeviceNetworkInfo"                         = "Microsoft Defender for Endpoint"
    "DeviceProcessEvents"                       = "Microsoft Defender for Endpoint"
    "DeviceRegistryEvents"                      = "Microsoft Defender for Endpoint"
    "DeviceTvmHardwareFirmware"                 = "Microsoft Defender for Endpoint"
    "DeviceTvmInfoGathering"                    = "Microsoft Defender for Endpoint"
    "DeviceTvmSecureConfigurationAssessment"    = "Microsoft Defender for Endpoint"
    "DeviceTvmSecureConfigurationAssessmentKB"  = "Microsoft Defender for Endpoint"
    "DeviceTvmSoftwareEvidenceBeta"             = "Microsoft Defender for Endpoint"
    "DeviceTvmSoftwareInventory"                = "Microsoft Defender for Endpoint"
    "DeviceTvmSoftwareVulnerabilities"          = "Microsoft Defender for Endpoint"
    "DeviceTvmSoftwareVulnerabilitiesKB"        = "Microsoft Defender for Endpoint"
    "DeviceTvmCertificateInfo"                  = "Microsoft Defender for Endpoint"
    "DeviceTvmBrowserExtensions"                = "Microsoft Defender for Endpoint"
    "DeviceBaselineComplianceAssessment"        = "Microsoft Defender for Endpoint"
    "DeviceBaselineComplianceAssessmentKB"      = "Microsoft Defender for Endpoint"
    "DeviceBaselineComplianceProfiles"          = "Microsoft Defender for Endpoint"

    # Microsoft Defender for Office 365
    "EmailAttachmentInfo"                       = "Microsoft Defender for Office 365"
    "EmailEvents"                               = "Microsoft Defender for Office 365"
    "EmailPostDeliveryEvents"                   = "Microsoft Defender for Office 365"
    "EmailUrlInfo"                              = "Microsoft Defender for Office 365"
    "UrlClickEvents"                            = "Microsoft Defender for Office 365"

    # Microsoft Defender for Identity
    "IdentityDirectoryEvents"                   = "Microsoft Defender for Identity"
    "IdentityLogonEvents"                       = "Microsoft Defender for Identity"
    "IdentityQueryEvents"                       = "Microsoft Defender for Identity"

    # Microsoft Defender for Cloud Apps
    "CloudAppEvents"                            = "Microsoft Defender for Cloud Apps"

    # Alert and incident tables
    "AlertEvidence"                             = "Microsoft Defender XDR"
    "AlertInfo"                                 = "Microsoft Defender XDR"

    # Microsoft Entra ID tables
    "AADSignInEventsBeta"                       = "Microsoft Entra ID"
    "AADSpnSignInEventsBeta"                    = "Microsoft Entra ID"

    # Exposure management tables
    "ExposureGraphEdges"                        = "Microsoft Security Exposure Management"
    "ExposureGraphNodes"                        = "Microsoft Security Exposure Management"

    # Newer GA / preview tables (2025+)
    "IdentityAccountInfo"                       = "Microsoft Defender for Identity"
    "EntraIdSignInEvents"                       = "Microsoft Entra ID"
    "EntraIdSpnSignInEvents"                    = "Microsoft Entra ID"
    "CloudStorageAggregatedEvents"              = "Microsoft Defender for Cloud Apps"
    "IdentityEvents"                            = "Microsoft Defender for Identity"
    "DisruptionAndResponseEvents"               = "Microsoft Defender XDR"
}

# Build a case-insensitive lookup
$XdrTableLookup = @{}
foreach ($table in $XdrTableRegistry.Keys) {
    $XdrTableLookup[$table.ToLower()] = $table
}

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

function Find-XdrTablesInQuery {
    <#
    .SYNOPSIS
        Parses a KQL query string and returns XDR table references found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Query
    )

    if ([string]::IsNullOrWhiteSpace($Query)) {
        return @()
    }

    # Strip KQL comments (// single-line)
    $cleanedQuery = ($Query -split "`n" | ForEach-Object {
        $_ -replace '//.*$', ''
    }) -join "`n"

    $foundTables = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($tableName in $XdrTableRegistry.Keys) {
        # Use word-boundary matching to avoid partial matches
        $pattern = "\b$([regex]::Escape($tableName))\b"
        if ($cleanedQuery -match $pattern) {
            if ($seen.Add($tableName)) {
                $foundTables.Add([PSCustomObject]@{
                    TableName   = $tableName
                    ProductArea = $XdrTableRegistry[$tableName]
                })
            }
        }
    }

    return $foundTables
}

function Get-AzAccessToken_Safe {
    <#
    .SYNOPSIS
        Retrieves an access token for Azure Management API, compatible with
        both older and newer versions of the Az.Accounts module.
    #>
    try {
        # Az.Accounts >= 5.x returns a SecureString by default
        $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com" -ErrorAction Stop
        if ($tokenObj.Token -is [System.Security.SecureString]) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenObj.Token)
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        return $tokenObj.Token
    }
    catch {
        throw "Failed to obtain access token. Ensure you are logged in with Connect-AzAccount. Error: $_"
    }
}

function Get-SentinelAnalyticRules {
    <#
    .SYNOPSIS
        Retrieves all Sentinel analytic rules via the Azure Management REST API.
    #>
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName
    )

    $token = Get-AzAccessToken_Safe
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    $apiVersion = "2024-09-01"
    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId" +
               "/resourceGroups/$ResourceGroupName" +
               "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
               "/providers/Microsoft.SecurityInsights/alertRules" +
               "?api-version=$apiVersion"

    $allRules = [System.Collections.Generic.List[PSObject]]::new()
    $uri = $baseUri

    do {
        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            throw "Failed to retrieve analytic rules (HTTP $statusCode). " +
                  "Verify subscription, resource group, and workspace names are correct. Error: $_"
        }

        if ($response.value) {
            foreach ($rule in $response.value) {
                $allRules.Add($rule)
            }
        }

        $uri = $response.nextLink
    } while ($uri)

    return $allRules
}

# ---------------------------------------------------------------------------
# Main script
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Sentinel Analytic Rules - Defender XDR Table Usage Scanner" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# --- Authenticate / verify Azure context ---
Write-Host "[1/4] Verifying Azure context..." -ForegroundColor Yellow

try {
    $context = Get-AzContext -ErrorAction Stop
    if (-not $context) {
        Write-Host "  No Azure context found. Running Connect-AzAccount..." -ForegroundColor Gray
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
    else {
        Write-Host "  Authenticated as: $($context.Account.Id)" -ForegroundColor Gray
        Write-Host "  Tenant:           $($context.Tenant.Id)" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Azure authentication failed. Please run Connect-AzAccount first. Error: $_"
    exit 1
}

# Set subscription context
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Write-Host "  Subscription:     $SubscriptionId" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to set subscription context to '$SubscriptionId'. Error: $_"
    exit 1
}

# --- Retrieve analytic rules ---
Write-Host ""
Write-Host "[2/4] Retrieving Sentinel analytic rules..." -ForegroundColor Yellow

$allRules = Get-SentinelAnalyticRules -SubscriptionId $SubscriptionId `
                                       -ResourceGroupName $ResourceGroupName `
                                       -WorkspaceName $WorkspaceName

# Filter to Scheduled and NRT rules (these are the ones with KQL queries)
$queryRules = $allRules | Where-Object {
    $_.kind -eq "Scheduled" -or $_.kind -eq "NRT"
}

if (-not $IncludeDisabled) {
    $queryRules = $queryRules | Where-Object {
        $_.properties.enabled -eq $true
    }
}

$totalRules = @($queryRules).Count
$statusLabel = if ($IncludeDisabled) { "all (including disabled)" } else { "enabled only" }
Write-Host "  Found $totalRules analytic rules ($statusLabel) with KQL queries." -ForegroundColor Gray

if ($totalRules -eq 0) {
    Write-Host ""
    Write-Host "  No analytic rules found to scan. Exiting." -ForegroundColor Gray
    exit 0
}

# --- Scan rules for XDR table references ---
Write-Host ""
Write-Host "[3/4] Scanning rules for Defender XDR table references..." -ForegroundColor Yellow

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$rulesWithXdr = 0

foreach ($rule in $queryRules) {
    $displayName = $rule.properties.displayName
    $severity    = $rule.properties.severity
    $enabled     = $rule.properties.enabled
    $ruleKind    = $rule.kind
    $query       = $rule.properties.query
    $tactics     = $rule.properties.tactics -join ", "
    $ruleId      = $rule.name

    $xdrTables = Find-XdrTablesInQuery -Query $query

    if ($xdrTables.Count -gt 0) {
        $rulesWithXdr++

        foreach ($tableMatch in $xdrTables) {
            $results.Add([PSCustomObject]@{
                RuleName    = $displayName
                RuleId      = $ruleId
                RuleKind    = $ruleKind
                Severity    = $severity
                Enabled     = $enabled
                Tactics     = $tactics
                XdrTable    = $tableMatch.TableName
                ProductArea = $tableMatch.ProductArea
            })
        }
    }
}

# --- Generate report ---
Write-Host ""
Write-Host "[4/4] Generating report..." -ForegroundColor Yellow
Write-Host ""

if ($results.Count -eq 0) {
    Write-Host "  No Defender XDR table references found in any analytic rules." -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# Summary statistics
$uniqueRules  = ($results | Select-Object -Property RuleName -Unique).Count
$uniqueTables = ($results | Select-Object -Property XdrTable -Unique).Count
$productAreas = ($results | Select-Object -Property ProductArea -Unique | ForEach-Object { $_.ProductArea })

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  SCAN RESULTS SUMMARY" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Total rules scanned:              $totalRules" -ForegroundColor White
Write-Host "  Rules referencing XDR tables:      $uniqueRules" -ForegroundColor White
Write-Host "  Unique XDR tables found:           $uniqueTables" -ForegroundColor White
Write-Host "  Defender product areas involved:   $($productAreas.Count)" -ForegroundColor White
Write-Host ""

# Table usage breakdown
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  XDR TABLE USAGE BREAKDOWN" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray

$tableGroups = $results | Group-Object -Property ProductArea | Sort-Object -Property Name
foreach ($group in $tableGroups) {
    Write-Host ""
    Write-Host "  $($group.Name)" -ForegroundColor Yellow
    $tableSubGroups = $group.Group | Group-Object -Property XdrTable | Sort-Object Count -Descending
    foreach ($tsg in $tableSubGroups) {
        $ruleCount = ($tsg.Group | Select-Object -Property RuleName -Unique).Count
        Write-Host "    - $($tsg.Name): used in $ruleCount rule(s)" -ForegroundColor Gray
    }
}

# Per-rule detail
Write-Host ""
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  RULES REFERENCING DEFENDER XDR TABLES" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray

$ruleGroups = $results | Group-Object -Property RuleName | Sort-Object -Property Name
$ruleIndex = 0

foreach ($rg in $ruleGroups) {
    $ruleIndex++
    $firstEntry = $rg.Group[0]
    $tables = ($rg.Group | ForEach-Object { $_.XdrTable }) -join ", "
    $enabledLabel = if ($firstEntry.Enabled) { "Enabled" } else { "Disabled" }

    Write-Host ""
    Write-Host "  [$ruleIndex] $($rg.Name)" -ForegroundColor White
    Write-Host "      Severity: $($firstEntry.Severity) | Status: $enabledLabel | Kind: $($firstEntry.RuleKind)" -ForegroundColor Gray
    if ($firstEntry.Tactics) {
        Write-Host "      Tactics:  $($firstEntry.Tactics)" -ForegroundColor Gray
    }
    Write-Host "      XDR Tables: $tables" -ForegroundColor Green
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

# --- Export if requested ---
switch ($OutputFormat) {
    "CSV" {
        if (-not $OutputPath) {
            $OutputPath = ".\SentinelXdrTableReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        }
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Report exported to: $OutputPath" -ForegroundColor Green
        Write-Host ""
    }
    "JSON" {
        if (-not $OutputPath) {
            $OutputPath = ".\SentinelXdrTableReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        }
        $reportObject = @{
            GeneratedAt       = (Get-Date -Format "o")
            Workspace         = $WorkspaceName
            SubscriptionId    = $SubscriptionId
            ResourceGroup     = $ResourceGroupName
            TotalRulesScanned = $totalRules
            RulesWithXdrTables = $uniqueRules
            UniqueXdrTables   = $uniqueTables
            ProductAreas      = $productAreas
            Rules             = @(
                foreach ($rg in $ruleGroups) {
                    $firstEntry = $rg.Group[0]
                    @{
                        RuleName    = $rg.Name
                        RuleId      = $firstEntry.RuleId
                        RuleKind    = $firstEntry.RuleKind
                        Severity    = $firstEntry.Severity
                        Enabled     = $firstEntry.Enabled
                        Tactics     = $firstEntry.Tactics
                        XdrTables   = @($rg.Group | ForEach-Object {
                            @{
                                TableName   = $_.XdrTable
                                ProductArea = $_.ProductArea
                            }
                        })
                    }
                }
            )
        }
        $reportObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "  Report exported to: $OutputPath" -ForegroundColor Green
        Write-Host ""
    }
    "Console" {
        # Already printed above
    }
}

Write-Host "Done." -ForegroundColor Cyan

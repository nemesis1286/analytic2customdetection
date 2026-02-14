<#
.SYNOPSIS
    Scans Sentinel analytic rules for Defender XDR table usage and optionally
    converts and deploys them as XDR custom detection rules.

.DESCRIPTION
    This script connects to a Microsoft Sentinel workspace, retrieves all
    analytic rules (Scheduled and NRT), parses their KQL queries for
    references to Defender XDR advanced hunting tables, and outputs a report.

    It supports three modes of operation:

    1. SCAN (default) - Report which analytic rules reference XDR tables.
    2. TRANSLATE (-Translate) - Dry-run preview showing how rules would be
       converted to XDR custom detections (query adaptation, frequency
       mapping, severity/MITRE mapping).
    3. DEPLOY (-Deploy) - Convert eligible rules and create them as custom
       detection rules in Defender XDR via the Microsoft Graph Security API.

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The resource group name containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name used by Sentinel.

.PARAMETER Translate
    Show a dry-run preview of converted custom detection rules without
    deploying them. Displays the adapted KQL query, mapped frequency,
    severity, and MITRE tactics for each eligible rule.

.PARAMETER Deploy
    Convert eligible Sentinel analytic rules and deploy them as custom
    detection rules in Defender XDR. Implies -Translate. Requires
    Microsoft Graph API permissions (CustomDetection.ReadWrite.All).

.PARAMETER SkipExisting
    When deploying, skip rules whose display name already exists in
    Defender XDR. Enabled by default. Use -SkipExisting:$false to
    allow duplicate names.

.PARAMETER RulePrefix
    Prefix to prepend to converted rule display names for traceability.
    Default: "[Sentinel] ".

.PARAMETER OutputFormat
    Output format for the report: Console, CSV, or JSON. Default is Console.

.PARAMETER OutputPath
    File path for CSV or JSON output. If not specified, a default filename
    is generated in the current directory.

.PARAMETER IncludeDisabled
    Include disabled analytic rules in the scan. By default, only enabled
    rules are checked.

.EXAMPLE
    # Scan only - report XDR table usage
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel"

.EXAMPLE
    # Translate - dry-run preview of conversion
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -Translate

.EXAMPLE
    # Deploy - convert and create rules in Defender XDR
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -Deploy

.EXAMPLE
    # Deploy with CSV export, including disabled rules
    .\Check-SentinelXdrTables.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -Deploy -IncludeDisabled -OutputFormat CSV
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
    [switch]$Translate,

    [Parameter(Mandatory = $false)]
    [switch]$Deploy,

    [Parameter(Mandatory = $false)]
    [bool]$SkipExisting = $true,

    [Parameter(Mandatory = $false)]
    [string]$RulePrefix = "[Sentinel] ",

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

# Deploy implies Translate
if ($Deploy) { $Translate = $true }

# ============================================================================
# CONSTANTS & REGISTRIES
# ============================================================================

# ---------------------------------------------------------------------------
# Defender XDR advanced hunting table registry
# ---------------------------------------------------------------------------
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

    # Newer GA / preview tables
    "IdentityAccountInfo"                       = "Microsoft Defender for Identity"
    "EntraIdSignInEvents"                       = "Microsoft Entra ID"
    "EntraIdSpnSignInEvents"                    = "Microsoft Entra ID"
    "CloudStorageAggregatedEvents"              = "Microsoft Defender for Cloud Apps"
    "IdentityEvents"                            = "Microsoft Defender for Identity"
    "DisruptionAndResponseEvents"               = "Microsoft Defender XDR"
}

# Case-insensitive lookup: lowercase -> canonical name
$XdrTableLookup = @{}
foreach ($table in $XdrTableRegistry.Keys) {
    $XdrTableLookup[$table.ToLower()] = $table
}

# Exposure management tables do NOT support the Timestamp column required
# for custom detections and must be excluded from conversion/deployment.
$ExposureManagementTables = [System.Collections.Generic.HashSet[string]]@(
    "ExposureGraphEdges"
    "ExposureGraphNodes"
)

# ---------------------------------------------------------------------------
# Sentinel -> XDR frequency mapping
# ---------------------------------------------------------------------------
# Sentinel uses ISO 8601 durations; XDR supports four fixed frequencies.
$FrequencyMap = @{
    "PT5M"  = "PT1H"
    "PT10M" = "PT1H"
    "PT15M" = "PT1H"
    "PT30M" = "PT1H"
    "PT1H"  = "PT1H"
    "PT2H"  = "PT3H"
    "PT3H"  = "PT3H"
    "PT4H"  = "PT12H"
    "PT6H"  = "PT12H"
    "PT12H" = "PT12H"
    "PT24H" = "PT24H"
    "P1D"   = "PT24H"
}

$FrequencyDisplayMap = @{
    "PT1H"  = "Every hour"
    "PT3H"  = "Every 3 hours"
    "PT12H" = "Every 12 hours"
    "PT24H" = "Every 24 hours"
}

# ---------------------------------------------------------------------------
# Sentinel -> XDR severity mapping
# ---------------------------------------------------------------------------
$SeverityMap = @{
    "Informational" = "informational"
    "Low"           = "low"
    "Medium"        = "medium"
    "High"          = "high"
    "informational" = "informational"
    "low"           = "low"
    "medium"        = "medium"
    "high"          = "high"
}

# ---------------------------------------------------------------------------
# Sentinel -> XDR MITRE ATT&CK tactic mapping
# ---------------------------------------------------------------------------
$TacticMap = @{
    "InitialAccess"       = "initialAccess"
    "Execution"           = "execution"
    "Persistence"         = "persistence"
    "PrivilegeEscalation" = "privilegeEscalation"
    "DefenseEvasion"      = "defenseEvasion"
    "CredentialAccess"    = "credentialAccess"
    "Discovery"           = "discovery"
    "LateralMovement"     = "lateralMovement"
    "Collection"          = "collection"
    "Exfiltration"        = "exfiltration"
    "CommandAndControl"   = "commandAndControl"
    "Impact"              = "impact"
    "Reconnaissance"      = "reconnaissance"
    "ResourceDevelopment" = "resourceDevelopment"
}

# ============================================================================
# FUNCTIONS
# ============================================================================

# ---------------------------------------------------------------------------
# KQL table scanning
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

function Get-PrimaryXdrTable {
    <#
    .SYNOPSIS
        Returns the first XDR table referenced in a KQL query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Query
    )

    if ([string]::IsNullOrWhiteSpace($Query)) { return $null }

    $cleanedQuery = ($Query -split "`n" | ForEach-Object {
        $_ -replace '//.*$', ''
    }) -join "`n"

    # Walk through tokens that look like identifiers and return the first XDR table
    $matches_found = [regex]::Matches($cleanedQuery, '\b([A-Z]\w+)\b')
    foreach ($m in $matches_found) {
        $token = $m.Groups[1].Value
        $canonical = $XdrTableLookup[$token.ToLower()]
        if ($canonical) {
            return $canonical
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# KQL query adaptation for XDR custom detections
# ---------------------------------------------------------------------------

function Convert-KqlForXdr {
    <#
    .SYNOPSIS
        Adapts a Sentinel KQL query for Defender XDR custom detection
        compatibility.
    .DESCRIPTION
        XDR custom detection queries must:
        1. Reference at least one advanced hunting table
        2. Project Timestamp and ReportId columns
        3. Not include Sentinel-specific time window filters (XDR handles
           scheduling natively)

        This function removes Sentinel time filters, replaces
        TimeGenerated with Timestamp, and ensures the required output
        columns are projected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter(Mandatory = $false)]
        [string]$PrimaryTable
    )

    $adapted = $Query.Trim()

    # --- Remove Sentinel-specific time filters ---
    # | where TimeGenerated > ago(1h)  /  >= ago(1d)  etc.
    $adapted = [regex]::Replace(
        $adapted,
        '\|\s*where\s+TimeGenerated\s*[><=!]+\s*ago\s*\([^)]+\)\s*',
        '',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # Replace remaining TimeGenerated references with Timestamp
    $adapted = [regex]::Replace(
        $adapted,
        '\bTimeGenerated\b',
        'Timestamp'
    )

    # Remove ingestion_time() filters
    $adapted = [regex]::Replace(
        $adapted,
        '\|\s*where\s+ingestion_time\s*\(\s*\)\s*[><=!]+\s*ago\s*\([^)]+\)\s*',
        '',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # --- Ensure required output columns (Timestamp, ReportId) ---
    $hasTimestamp = [regex]::IsMatch($adapted, '\bTimestamp\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $hasReportId  = [regex]::IsMatch($adapted, '\bReportId\b',  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($hasTimestamp -and $hasReportId) {
        return $adapted
    }

    $missing = @()
    if (-not $hasTimestamp) { $missing += "Timestamp" }
    if (-not $hasReportId)  { $missing += "ReportId" }

    # Check if query ends with a project statement we can extend
    $projectMatch = [regex]::Match(
        $adapted,
        '(\|\s*project(?:-keep)?\s+)(.*?)$',
        ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
         [System.Text.RegularExpressions.RegexOptions]::Singleline)
    )

    if ($projectMatch.Success) {
        $existingCols = $projectMatch.Groups[2].Value.Trim()
        $newCols = $missing -join ", "
        $adapted = $adapted.Substring(0, $projectMatch.Index) +
                   $projectMatch.Groups[1].Value +
                   $existingCols + ", " + $newCols
    }
    else {
        # Append an extend to include required columns
        $extendParts = $missing | ForEach-Object { "$_ = $_" }
        $adapted = $adapted + "`n| extend " + ($extendParts -join ", ")
    }

    return $adapted
}

# ---------------------------------------------------------------------------
# Frequency mapping
# ---------------------------------------------------------------------------

function ConvertTo-XdrFrequency {
    <#
    .SYNOPSIS
        Maps a Sentinel ISO 8601 query frequency to the nearest XDR
        detection frequency.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SentinelFrequency
    )

    if ([string]::IsNullOrWhiteSpace($SentinelFrequency)) {
        return "PT24H"
    }

    # Direct lookup
    if ($FrequencyMap.ContainsKey($SentinelFrequency.ToUpper())) {
        return $FrequencyMap[$SentinelFrequency.ToUpper()]
    }

    # Parse ISO 8601 duration to hours and pick the best match
    $durationMatch = [regex]::Match(
        $SentinelFrequency,
        '^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($durationMatch.Success) {
        $days    = if ($durationMatch.Groups[1].Value) { [int]$durationMatch.Groups[1].Value } else { 0 }
        $hours   = if ($durationMatch.Groups[2].Value) { [int]$durationMatch.Groups[2].Value } else { 0 }
        $minutes = if ($durationMatch.Groups[3].Value) { [int]$durationMatch.Groups[3].Value } else { 0 }
        $totalHours = $days * 24 + $hours + $minutes / 60.0

        if ($totalHours -le 1)  { return "PT1H" }
        if ($totalHours -le 3)  { return "PT3H" }
        if ($totalHours -le 12) { return "PT12H" }
        return "PT24H"
    }

    # Fallback
    return "PT24H"
}

# ---------------------------------------------------------------------------
# Full rule conversion
# ---------------------------------------------------------------------------

function ConvertTo-XdrCustomDetection {
    <#
    .SYNOPSIS
        Converts a Sentinel analytic rule into a Defender XDR custom
        detection rule object.
    .OUTPUTS
        A PSCustomObject representing the converted rule, or $null if
        the rule is not eligible for conversion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$SentinelRule,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[PSCustomObject]]$XdrTables,

        [Parameter(Mandatory = $false)]
        [string]$Prefix = "[Sentinel] "
    )

    $props = $SentinelRule.properties

    # Check that at least one referenced table supports custom detections
    # (Exposure Management tables are excluded)
    $compatibleTables = @($XdrTables | Where-Object {
        -not $ExposureManagementTables.Contains($_.TableName)
    })

    if ($compatibleTables.Count -eq 0) {
        return $null
    }

    # Adapt the KQL query
    $primaryTable = Get-PrimaryXdrTable -Query $props.query
    $adaptedQuery = Convert-KqlForXdr -Query $props.query -PrimaryTable $primaryTable

    # Map frequency (NRT rules map to the fastest available: PT1H)
    $xdrFrequency = if ($SentinelRule.kind -eq "NRT") {
        "PT1H"
    }
    else {
        ConvertTo-XdrFrequency -SentinelFrequency $props.queryFrequency
    }

    # Map severity
    $xdrSeverity = $SeverityMap[$props.severity]
    if (-not $xdrSeverity) { $xdrSeverity = "medium" }

    # Map MITRE tactics
    $xdrTactics = @()
    if ($props.tactics) {
        foreach ($tactic in $props.tactics) {
            $mapped = $TacticMap[$tactic]
            if ($mapped) { $xdrTactics += $mapped }
        }
    }

    # Map MITRE techniques
    $xdrTechniques = @()
    if ($props.techniques) {
        $xdrTechniques = @($props.techniques)
    }

    # Build display name with prefix and enforce 256-char limit
    $displayName = "$Prefix$($props.displayName)"
    if ($displayName.Length -gt 256) {
        $displayName = $displayName.Substring(0, 253) + "..."
    }

    # Build description with provenance
    $description = $props.description
    if ($description) {
        $description += "`n`n"
    }
    $description += "[Auto-converted from Sentinel analytic rule: $($props.displayName)]"

    # Primary alert category from the first MITRE tactic, or "General"
    $alertCategory = if ($xdrTactics.Count -gt 0) { $xdrTactics[0] } else { "General" }

    return [PSCustomObject]@{
        DisplayName       = $displayName
        OriginalName      = $props.displayName
        SentinelRuleId    = $SentinelRule.name
        RuleKind          = $SentinelRule.kind
        QueryText         = $adaptedQuery
        OriginalQuery     = $props.query
        Frequency         = $xdrFrequency
        FrequencyLabel    = $FrequencyDisplayMap[$xdrFrequency]
        Severity          = $xdrSeverity
        MitreTactics      = $xdrTactics
        MitreTechniques   = $xdrTechniques
        Description       = $description
        AlertCategory     = $alertCategory
        XdrTables         = @($compatibleTables | ForEach-Object { $_.TableName })
        ProductAreas      = @($compatibleTables | Select-Object -Property ProductArea -Unique | ForEach-Object { $_.ProductArea })
        RecommendedActions = "Investigate the alert in Microsoft 365 Defender. This detection was auto-converted from a Sentinel analytic rule."
    }
}

# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

function Get-AzAccessToken_Safe {
    <#
    .SYNOPSIS
        Retrieves an access token for a given resource, compatible with
        both older and newer versions of the Az.Accounts module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ResourceUrl = "https://management.azure.com"
    )

    try {
        $tokenObj = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
        if ($tokenObj.Token -is [System.Security.SecureString]) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenObj.Token)
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        return $tokenObj.Token
    }
    catch {
        throw "Failed to obtain access token for '$ResourceUrl'. Ensure you are logged in with Connect-AzAccount. Error: $_"
    }
}

# ---------------------------------------------------------------------------
# Sentinel API
# ---------------------------------------------------------------------------

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

    $token = Get-AzAccessToken_Safe -ResourceUrl "https://management.azure.com"
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
# Defender XDR Graph API - Custom Detection Rules
# ---------------------------------------------------------------------------

function Get-GraphHeaders {
    <#
    .SYNOPSIS
        Builds authorization headers for Microsoft Graph API calls.
    #>
    $token = Get-AzAccessToken_Safe -ResourceUrl "https://graph.microsoft.com"
    return @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
}

function Get-ExistingXdrDetectionRules {
    <#
    .SYNOPSIS
        Lists all existing custom detection rules in Defender XDR via
        the Microsoft Graph Security API.
    #>
    [CmdletBinding()]
    param()

    $headers = Get-GraphHeaders
    $url = "https://graph.microsoft.com/v1.0/security/rules/detectionRules"

    $allRules = [System.Collections.Generic.List[PSObject]]::new()

    while ($url) {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
            }
            throw "Failed to list existing XDR custom detection rules (HTTP $statusCode). " +
                  "Ensure your account has CustomDetection.ReadWrite.All permissions. Error: $_"
        }

        if ($response.value) {
            foreach ($rule in $response.value) {
                $allRules.Add($rule)
            }
        }

        $url = $response.'@odata.nextLink'
    }

    return $allRules
}

function New-XdrCustomDetectionRule {
    <#
    .SYNOPSIS
        Creates a single custom detection rule in Defender XDR via the
        Microsoft Graph Security API.
    .OUTPUTS
        A PSCustomObject with Success, RuleId, DisplayName, and Error fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ConvertedRule
    )

    $headers = Get-GraphHeaders
    $url = "https://graph.microsoft.com/v1.0/security/rules/detectionRules"

    # Build the Graph API payload matching the schema
    $payload = @{
        displayName      = $ConvertedRule.DisplayName
        isEnabled        = $true
        queryCondition   = @{
            queryText              = $ConvertedRule.QueryText
            lastModifiedDateTime   = $null
        }
        schedule         = @{
            period = $ConvertedRule.Frequency
        }
        detectionAction  = @{
            alertTemplate       = @{
                title               = $ConvertedRule.DisplayName
                description         = $ConvertedRule.Description
                severity            = $ConvertedRule.Severity
                category            = $ConvertedRule.AlertCategory
                mitreTechniques     = @($ConvertedRule.MitreTechniques)
                recommendedActions  = $ConvertedRule.RecommendedActions
                impactedAssets      = @()
            }
            organizationalScope = $null
            responseActions     = @()
        }
    }

    $body = $payload | ConvertTo-Json -Depth 10 -Compress

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body -ErrorAction Stop
        return [PSCustomObject]@{
            Success     = $true
            RuleId      = $response.id
            DisplayName = $ConvertedRule.DisplayName
            Error       = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        try {
            $errorStream = $_.Exception.Response.GetResponseStream()
            $reader = [System.IO.StreamReader]::new($errorStream)
            $errorBody = $reader.ReadToEnd() | ConvertFrom-Json
            if ($errorBody.error.message) {
                $errorMessage = $errorBody.error.message
            }
        }
        catch { }

        return [PSCustomObject]@{
            Success     = $false
            RuleId      = $null
            DisplayName = $ConvertedRule.DisplayName
            Error       = $errorMessage
        }
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

$modeLabel = if ($Deploy) { "Scan + Translate + Deploy" }
             elseif ($Translate) { "Scan + Translate" }
             else { "Scan" }

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Sentinel Analytic Rules - Defender XDR Table Usage Scanner" -ForegroundColor Cyan
Write-Host "  Mode: $modeLabel" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Authenticate / verify Azure context
# ---------------------------------------------------------------------------
$totalSteps = if ($Deploy) { 6 } elseif ($Translate) { 5 } else { 4 }

Write-Host "[1/$totalSteps] Verifying Azure context..." -ForegroundColor Yellow

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

try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Write-Host "  Subscription:     $SubscriptionId" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to set subscription context to '$SubscriptionId'. Error: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 2: Retrieve analytic rules
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/$totalSteps] Retrieving Sentinel analytic rules..." -ForegroundColor Yellow

$allRules = Get-SentinelAnalyticRules -SubscriptionId $SubscriptionId `
                                       -ResourceGroupName $ResourceGroupName `
                                       -WorkspaceName $WorkspaceName

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

# ---------------------------------------------------------------------------
# Step 3: Scan rules for XDR table references
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/$totalSteps] Scanning rules for Defender XDR table references..." -ForegroundColor Yellow

$scanResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$xdrEligibleRules = [System.Collections.Generic.List[PSObject]]::new()
$xdrEligibleTables = @{}  # ruleId -> table list

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
        $xdrEligibleRules.Add($rule)
        $xdrEligibleTables[$ruleId] = $xdrTables

        foreach ($tableMatch in $xdrTables) {
            $scanResults.Add([PSCustomObject]@{
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

# ---------------------------------------------------------------------------
# Scan report (always shown)
# ---------------------------------------------------------------------------
Write-Host ""

if ($scanResults.Count -eq 0) {
    Write-Host "  No Defender XDR table references found in any analytic rules." -ForegroundColor Gray
    Write-Host ""
    exit 0
}

$uniqueRules  = ($scanResults | Select-Object -Property RuleName -Unique).Count
$uniqueTables = ($scanResults | Select-Object -Property XdrTable -Unique).Count
$productAreas = ($scanResults | Select-Object -Property ProductArea -Unique | ForEach-Object { $_.ProductArea })

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

$tableGroups = $scanResults | Group-Object -Property ProductArea | Sort-Object -Property Name
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

$ruleGroups = $scanResults | Group-Object -Property RuleName | Sort-Object -Property Name
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

# ---------------------------------------------------------------------------
# Step 4 (Translate): Convert rules to XDR custom detection format
# ---------------------------------------------------------------------------
$convertedRules = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedConversions = [System.Collections.Generic.List[string]]::new()

if ($Translate) {
    $stepNum = 4
    Write-Host "[${stepNum}/$totalSteps] Translating eligible rules to XDR custom detection format..." -ForegroundColor Yellow
    Write-Host ""

    foreach ($rule in $xdrEligibleRules) {
        $ruleId = $rule.name
        $xdrTables = $xdrEligibleTables[$ruleId]

        $converted = ConvertTo-XdrCustomDetection -SentinelRule $rule `
                                                   -XdrTables $xdrTables `
                                                   -Prefix $RulePrefix

        if ($converted) {
            $convertedRules.Add($converted)
        }
        else {
            $skippedConversions.Add($rule.properties.displayName)
        }
    }

    # --- Conversion report ---
    Write-Host "======================================================================" -ForegroundColor Magenta
    Write-Host "  TRANSLATION RESULTS" -ForegroundColor Magenta
    Write-Host "======================================================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Eligible rules found:   $($xdrEligibleRules.Count)" -ForegroundColor White
    Write-Host "  Successfully converted: $($convertedRules.Count)" -ForegroundColor White
    Write-Host "  Skipped (incompatible): $($skippedConversions.Count)" -ForegroundColor White
    Write-Host ""

    if ($skippedConversions.Count -gt 0) {
        Write-Host "  Skipped rules (only use Exposure Management tables):" -ForegroundColor DarkGray
        foreach ($name in $skippedConversions) {
            Write-Host "    - $name" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Show each converted rule
    $convIndex = 0
    foreach ($cr in $convertedRules) {
        $convIndex++
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  [$convIndex] $($cr.DisplayName)" -ForegroundColor White
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Original Name:   $($cr.OriginalName)" -ForegroundColor Gray
        Write-Host "  Sentinel Rule ID:$($cr.SentinelRuleId)" -ForegroundColor Gray
        Write-Host "  Kind:            $($cr.RuleKind)" -ForegroundColor Gray
        Write-Host "  Severity:        $($cr.Severity)" -ForegroundColor Gray
        Write-Host "  Frequency:       $($cr.Frequency) ($($cr.FrequencyLabel))" -ForegroundColor Gray
        Write-Host "  Alert Category:  $($cr.AlertCategory)" -ForegroundColor Gray
        if ($cr.MitreTactics.Count -gt 0) {
            Write-Host "  MITRE Tactics:   $($cr.MitreTactics -join ', ')" -ForegroundColor Gray
        }
        if ($cr.MitreTechniques.Count -gt 0) {
            Write-Host "  MITRE Techniques:$($cr.MitreTechniques -join ', ')" -ForegroundColor Gray
        }
        Write-Host "  XDR Tables:      $($cr.XdrTables -join ', ')" -ForegroundColor Green
        Write-Host "  Product Areas:   $($cr.ProductAreas -join ', ')" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Adapted KQL Query:" -ForegroundColor Cyan
        # Show the adapted query, indented
        $cr.QueryText -split "`n" | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkCyan
        }
        Write-Host ""
    }

    Write-Host "======================================================================" -ForegroundColor Magenta
    Write-Host ""

    if ($convertedRules.Count -eq 0) {
        Write-Host "  No rules were eligible for conversion. Exiting." -ForegroundColor Gray
        Write-Host ""
        exit 0
    }
}

# ---------------------------------------------------------------------------
# Step 5 (Deploy): Create custom detection rules in Defender XDR
# ---------------------------------------------------------------------------
if ($Deploy) {
    $stepNum = 5
    Write-Host "[${stepNum}/$totalSteps] Deploying custom detection rules to Defender XDR..." -ForegroundColor Yellow
    Write-Host ""

    # Validate Graph API access
    Write-Host "  Validating Microsoft Graph API access..." -ForegroundColor Gray
    try {
        $graphToken = Get-AzAccessToken_Safe -ResourceUrl "https://graph.microsoft.com"
        Write-Host "  Graph API token acquired." -ForegroundColor Gray
    }
    catch {
        Write-Error "Cannot obtain Microsoft Graph API token. Ensure your account has been granted access to the Graph Security API. Error: $_"
        exit 1
    }

    # Check for existing rules if SkipExisting is enabled
    $existingRuleNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    if ($SkipExisting) {
        Write-Host "  Fetching existing XDR custom detection rules..." -ForegroundColor Gray
        try {
            $existingRules = Get-ExistingXdrDetectionRules
            foreach ($er in $existingRules) {
                [void]$existingRuleNames.Add($er.displayName)
            }
            Write-Host "  Found $($existingRuleNames.Count) existing custom detection rule(s)." -ForegroundColor Gray
        }
        catch {
            Write-Warning "Could not fetch existing rules. Proceeding without duplicate check. Error: $_"
        }
    }

    Write-Host ""

    # Deploy each converted rule
    $deployResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $succeeded = 0
    $skipped   = 0
    $failed    = 0

    foreach ($cr in $convertedRules) {
        # Check for existing rule
        if ($SkipExisting -and $existingRuleNames.Contains($cr.DisplayName)) {
            Write-Host "  SKIP  $($cr.DisplayName)" -ForegroundColor DarkYellow
            Write-Host "        Rule already exists in Defender XDR." -ForegroundColor DarkGray
            $skipped++
            $deployResults.Add([PSCustomObject]@{
                DisplayName    = $cr.DisplayName
                OriginalName   = $cr.OriginalName
                SentinelRuleId = $cr.SentinelRuleId
                Status         = "Skipped"
                RuleId         = $null
                Error          = "Rule already exists"
            })
            continue
        }

        Write-Host "  CREATE $($cr.DisplayName)..." -ForegroundColor White -NoNewline
        $result = New-XdrCustomDetectionRule -ConvertedRule $cr

        if ($result.Success) {
            Write-Host " OK (id=$($result.RuleId))" -ForegroundColor Green
            $succeeded++
            $deployResults.Add([PSCustomObject]@{
                DisplayName    = $cr.DisplayName
                OriginalName   = $cr.OriginalName
                SentinelRuleId = $cr.SentinelRuleId
                Status         = "Created"
                RuleId         = $result.RuleId
                Error          = $null
            })
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "        Error: $($result.Error)" -ForegroundColor Red
            $failed++
            $deployResults.Add([PSCustomObject]@{
                DisplayName    = $cr.DisplayName
                OriginalName   = $cr.OriginalName
                SentinelRuleId = $cr.SentinelRuleId
                Status         = "Failed"
                RuleId         = $null
                Error          = $result.Error
            })
        }
    }

    # Deployment summary
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Blue
    Write-Host "  DEPLOYMENT RESULTS" -ForegroundColor Blue
    Write-Host "======================================================================" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  Created:  $succeeded" -ForegroundColor Green
    Write-Host "  Skipped:  $skipped" -ForegroundColor DarkYellow
    Write-Host "  Failed:   $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })
    Write-Host "  Total:    $($convertedRules.Count)" -ForegroundColor White
    Write-Host ""

    if ($failed -gt 0) {
        Write-Host "  Failed rules:" -ForegroundColor Red
        foreach ($dr in ($deployResults | Where-Object { $_.Status -eq "Failed" })) {
            Write-Host "    - $($dr.DisplayName): $($dr.Error)" -ForegroundColor Red
        }
        Write-Host ""
    }

    Write-Host "======================================================================" -ForegroundColor Blue
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step N: Export
# ---------------------------------------------------------------------------
$stepNum = $totalSteps
Write-Host "[$stepNum/$totalSteps] Generating export..." -ForegroundColor Yellow

switch ($OutputFormat) {
    "CSV" {
        if (-not $OutputPath) {
            $OutputPath = ".\SentinelXdrTableReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        }
        if ($Deploy) {
            # Export deployment results
            $deployResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        }
        elseif ($Translate) {
            # Export conversion results
            $convertedRules | Select-Object DisplayName, OriginalName, SentinelRuleId, RuleKind, `
                Severity, Frequency, FrequencyLabel, AlertCategory, `
                @{N='MitreTactics';E={$_.MitreTactics -join '; '}}, `
                @{N='MitreTechniques';E={$_.MitreTechniques -join '; '}}, `
                @{N='XdrTables';E={$_.XdrTables -join '; '}}, `
                @{N='ProductAreas';E={$_.ProductAreas -join '; '}} |
                Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        }
        else {
            # Export scan results
            $scanResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        }
        Write-Host "  Report exported to: $OutputPath" -ForegroundColor Green
        Write-Host ""
    }
    "JSON" {
        if (-not $OutputPath) {
            $OutputPath = ".\SentinelXdrTableReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        }
        $reportObject = @{
            GeneratedAt        = (Get-Date -Format "o")
            Mode               = $modeLabel
            Workspace          = $WorkspaceName
            SubscriptionId     = $SubscriptionId
            ResourceGroup      = $ResourceGroupName
            TotalRulesScanned  = $totalRules
            RulesWithXdrTables = $uniqueRules
            UniqueXdrTables    = $uniqueTables
            ProductAreas       = $productAreas
        }

        # Scan results (always included)
        $reportObject["ScanResults"] = @(
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

        # Translation results (if Translate or Deploy mode)
        if ($Translate) {
            $reportObject["ConvertedRulesCount"] = $convertedRules.Count
            $reportObject["SkippedConversions"]  = @($skippedConversions)
            $reportObject["ConvertedRules"] = @(
                foreach ($cr in $convertedRules) {
                    @{
                        DisplayName      = $cr.DisplayName
                        OriginalName     = $cr.OriginalName
                        SentinelRuleId   = $cr.SentinelRuleId
                        RuleKind         = $cr.RuleKind
                        Severity         = $cr.Severity
                        Frequency        = $cr.Frequency
                        FrequencyLabel   = $cr.FrequencyLabel
                        AlertCategory    = $cr.AlertCategory
                        MitreTactics     = @($cr.MitreTactics)
                        MitreTechniques  = @($cr.MitreTechniques)
                        XdrTables        = @($cr.XdrTables)
                        ProductAreas     = @($cr.ProductAreas)
                        AdaptedQuery     = $cr.QueryText
                        OriginalQuery    = $cr.OriginalQuery
                    }
                }
            )
        }

        # Deployment results (if Deploy mode)
        if ($Deploy) {
            $reportObject["DeploymentResults"] = @{
                Created = $succeeded
                Skipped = $skipped
                Failed  = $failed
                Details = @(
                    foreach ($dr in $deployResults) {
                        @{
                            DisplayName    = $dr.DisplayName
                            OriginalName   = $dr.OriginalName
                            SentinelRuleId = $dr.SentinelRuleId
                            Status         = $dr.Status
                            RuleId         = $dr.RuleId
                            Error          = $dr.Error
                        }
                    }
                )
            }
        }

        $reportObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "  Report exported to: $OutputPath" -ForegroundColor Green
        Write-Host ""
    }
    "Console" {
        Write-Host "  Output displayed above." -ForegroundColor Gray
        Write-Host ""
    }
}

Write-Host "Done." -ForegroundColor Cyan

<#
.SYNOPSIS
    Unit tests for Check-SentinelXdrTables.ps1

.DESCRIPTION
    Tests the pure-logic functions from the scanner script:
    - Find-XdrTablesInQuery   (KQL table detection)
    - Get-PrimaryXdrTable     (primary table identification)
    - Convert-KqlForXdr       (KQL query adaptation)
    - ConvertTo-XdrFrequency  (frequency mapping)
    - ConvertTo-XdrCustomDetection (full rule conversion)

    Uses a lightweight assertion framework so no external modules
    (e.g. Pester) are required.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# Lightweight test framework
# ============================================================================

$script:TestCount   = 0
$script:PassCount   = 0
$script:FailCount   = 0
$script:FailDetails = [System.Collections.Generic.List[string]]::new()

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    $script:TestCount++
    if ($Expected -eq $Actual) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message`n    Expected: $Expected`n    Actual:   $Actual"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:TestCount++
    if ($Condition) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message (expected True, got False)"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-False {
    param([bool]$Condition, [string]$Message)
    Assert-True -Condition (-not $Condition) -Message $Message
}

function Assert-Null {
    param($Value, [string]$Message)
    $script:TestCount++
    if ($null -eq $Value) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message (expected null, got '$Value')"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-NotNull {
    param($Value, [string]$Message)
    $script:TestCount++
    if ($null -ne $Value) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message (expected non-null, got null)"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-Contains {
    param([string]$Haystack, [string]$Needle, [string]$Message)
    $script:TestCount++
    if ($Haystack.Contains($Needle)) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message`n    String does not contain '$Needle'"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-NotContains {
    param([string]$Haystack, [string]$Needle, [string]$Message)
    $script:TestCount++
    if (-not $Haystack.Contains($Needle)) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message`n    String should not contain '$Needle'"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Assert-ArrayContains {
    param([array]$Array, $Value, [string]$Message)
    $script:TestCount++
    if ($Array -contains $Value) {
        $script:PassCount++
    }
    else {
        $script:FailCount++
        $detail = "  FAIL: $Message`n    Array does not contain '$Value'. Contents: $($Array -join ', ')"
        $script:FailDetails.Add($detail)
        Write-Host $detail -ForegroundColor Red
    }
}

function Write-TestSection {
    param([string]$Name)
    Write-Host ""
    Write-Host "  --- $Name ---" -ForegroundColor Cyan
}

# ============================================================================
# Load functions under test
# ============================================================================
# We extract everything between the constants start and the "MAIN SCRIPT"
# marker from the source script, which gives us all variable definitions and
# function definitions without executing the main flow.

$scriptPath = Join-Path $PSScriptRoot "Check-SentinelXdrTables.ps1"
$scriptContent = Get-Content -Path $scriptPath -Raw

# Extract from after the param block to just before MAIN SCRIPT
$startMarker = "# ============================================================================`n# CONSTANTS & REGISTRIES"
$endMarker   = "# ============================================================================`n# MAIN SCRIPT"

$startIdx = $scriptContent.IndexOf($startMarker)
$endIdx   = $scriptContent.IndexOf($endMarker)

if ($startIdx -lt 0 -or $endIdx -lt 0) {
    Write-Error "Could not locate CONSTANTS/FUNCTIONS or MAIN SCRIPT markers in $scriptPath"
    exit 1
}

$functionsBlock = $scriptContent.Substring($startIdx, $endIdx - $startIdx)

# Execute the extracted block to define all variables and functions in this scope
Invoke-Expression $functionsBlock

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Check-SentinelXdrTables.ps1 - Unit Tests" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# ============================================================================
# TEST: XDR Table Registry
# ============================================================================
Write-TestSection "XDR Table Registry"

Assert-True -Condition ($XdrTableRegistry.Count -ge 40) `
    -Message "Registry should contain at least 40 tables (got $($XdrTableRegistry.Count))"

Assert-Equal -Expected "Microsoft Defender for Endpoint" `
    -Actual $XdrTableRegistry["DeviceProcessEvents"] `
    -Message "DeviceProcessEvents -> Defender for Endpoint"

Assert-Equal -Expected "Microsoft Defender for Office 365" `
    -Actual $XdrTableRegistry["EmailEvents"] `
    -Message "EmailEvents -> Defender for Office 365"

Assert-Equal -Expected "Microsoft Defender for Identity" `
    -Actual $XdrTableRegistry["IdentityLogonEvents"] `
    -Message "IdentityLogonEvents -> Defender for Identity"

Assert-Equal -Expected "Microsoft Defender for Cloud Apps" `
    -Actual $XdrTableRegistry["CloudAppEvents"] `
    -Message "CloudAppEvents -> Defender for Cloud Apps"

Assert-Equal -Expected "Microsoft Defender XDR" `
    -Actual $XdrTableRegistry["AlertInfo"] `
    -Message "AlertInfo -> Defender XDR"

Assert-Equal -Expected "Microsoft Entra ID" `
    -Actual $XdrTableRegistry["AADSignInEventsBeta"] `
    -Message "AADSignInEventsBeta -> Entra ID"

Assert-Equal -Expected "Microsoft Security Exposure Management" `
    -Actual $XdrTableRegistry["ExposureGraphEdges"] `
    -Message "ExposureGraphEdges -> Exposure Management"

# Case-insensitive lookup
Assert-Equal -Expected "DeviceEvents" `
    -Actual $XdrTableLookup["deviceevents"] `
    -Message "Case-insensitive lookup: deviceevents -> DeviceEvents"

# Exposure Management exclusion set
Assert-True -Condition $ExposureManagementTables.Contains("ExposureGraphEdges") `
    -Message "ExposureGraphEdges is in the exclusion set"
Assert-True -Condition $ExposureManagementTables.Contains("ExposureGraphNodes") `
    -Message "ExposureGraphNodes is in the exclusion set"
Assert-False -Condition $ExposureManagementTables.Contains("DeviceEvents") `
    -Message "DeviceEvents is NOT in the exclusion set"

# ============================================================================
# TEST: Find-XdrTablesInQuery
# ============================================================================
Write-TestSection "Find-XdrTablesInQuery"

# Basic single table detection
$result = Find-XdrTablesInQuery -Query "DeviceProcessEvents | where FileName == 'cmd.exe'"
Assert-Equal -Expected 1 -Actual $result.Count -Message "Detect single table"
Assert-Equal -Expected "DeviceProcessEvents" -Actual $result[0].TableName -Message "Correct table name"
Assert-Equal -Expected "Microsoft Defender for Endpoint" -Actual $result[0].ProductArea -Message "Correct product area"

# Multiple tables (union)
$result = Find-XdrTablesInQuery -Query @"
DeviceProcessEvents
| union DeviceFileEvents, DeviceNetworkEvents
| where Timestamp > ago(1h)
"@
Assert-True -Condition ($result.Count -ge 3) `
    -Message "Detect multiple tables in union (found $($result.Count))"
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-ArrayContains -Array $tableNames -Value "DeviceProcessEvents" -Message "Contains DeviceProcessEvents"
Assert-ArrayContains -Array $tableNames -Value "DeviceFileEvents" -Message "Contains DeviceFileEvents"
Assert-ArrayContains -Array $tableNames -Value "DeviceNetworkEvents" -Message "Contains DeviceNetworkEvents"

# Table in join
$result = Find-XdrTablesInQuery -Query @"
DeviceLogonEvents
| join kind=inner (DeviceInfo | project DeviceId, OSPlatform) on DeviceId
"@
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-ArrayContains -Array $tableNames -Value "DeviceLogonEvents" -Message "Detects table before join"
Assert-ArrayContains -Array $tableNames -Value "DeviceInfo" -Message "Detects table inside join"

# No false positives - KQL keyword not mistaken for table
$result = Find-XdrTablesInQuery -Query @"
let myData = datatable(col1:string)["a","b"];
myData
| where col1 == "a"
"@
Assert-Equal -Expected 0 -Actual @($result).Count -Message "No false positives on non-XDR query"

# Comment stripping
$result = Find-XdrTablesInQuery -Query @"
// This query uses DeviceProcessEvents
DeviceNetworkEvents
| where RemoteUrl has "malicious.com"
"@
$tableNames = $result | ForEach-Object { $_.TableName }
# DeviceProcessEvents appears in a comment - should still be found by word-boundary
# since comment stripping removes line comments, it should only find DeviceNetworkEvents
Assert-ArrayContains -Array $tableNames -Value "DeviceNetworkEvents" -Message "Finds table in active query line"

# Empty/null query
$result = Find-XdrTablesInQuery -Query ""
Assert-Equal -Expected 0 -Actual @($result).Count -Message "Empty query returns empty"

$result = Find-XdrTablesInQuery -Query "   "
Assert-Equal -Expected 0 -Actual @($result).Count -Message "Whitespace query returns empty"

# Email tables
$result = Find-XdrTablesInQuery -Query "EmailEvents | where Subject has 'phishing'"
Assert-Equal -Expected 1 -Actual @($result).Count -Message "Detects email table"
Assert-Equal -Expected "Microsoft Defender for Office 365" -Actual $result[0].ProductArea -Message "Email table product area"

# Identity tables
$result = Find-XdrTablesInQuery -Query "IdentityLogonEvents | where LogonType == 'Interactive'"
Assert-Equal -Expected 1 -Actual @($result).Count -Message "Detects identity table"

# Partial name should not match (no false partial matches)
$result = Find-XdrTablesInQuery -Query "let DeviceEventsCustom = externaldata(col:string)[@'path']; DeviceEventsCustom"
Assert-Equal -Expected 0 -Actual @($result).Count -Message "No partial match on DeviceEventsCustom"

# ============================================================================
# TEST: Get-PrimaryXdrTable
# ============================================================================
Write-TestSection "Get-PrimaryXdrTable"

$primary = Get-PrimaryXdrTable -Query "DeviceProcessEvents | where FileName == 'cmd.exe'"
Assert-Equal -Expected "DeviceProcessEvents" -Actual $primary -Message "Primary table is DeviceProcessEvents"

$primary = Get-PrimaryXdrTable -Query @"
let processes = DeviceProcessEvents | where FileName == 'cmd.exe';
let files = DeviceFileEvents | where FileName == 'payload.exe';
processes | join files on DeviceId
"@
Assert-Equal -Expected "DeviceProcessEvents" -Actual $primary -Message "Primary table is first referenced"

$primary = Get-PrimaryXdrTable -Query "// nothing useful here"
Assert-Null -Value $primary -Message "Returns null for non-XDR query"

$primary = Get-PrimaryXdrTable -Query ""
Assert-Null -Value $primary -Message "Returns null for empty query"

# ============================================================================
# TEST: Convert-KqlForXdr
# ============================================================================
Write-TestSection "Convert-KqlForXdr"

# TimeGenerated removal
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName == 'cmd.exe'
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated filter removed"
Assert-Contains -Haystack $adapted -Needle "FileName" `
    -Message "Detection logic preserved"

# TimeGenerated replacement (non-filter usage)
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| project TimeGenerated, DeviceName, FileName
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated replaced in project"
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Replaced with Timestamp"

# ingestion_time() filter removal
$adapted = Convert-KqlForXdr -Query @"
DeviceEvents
| where ingestion_time() > ago(2h)
| where ActionType == 'ProcessCreated'
"@
Assert-NotContains -Haystack $adapted -Needle "ingestion_time" `
    -Message "ingestion_time filter removed"

# Required columns: Timestamp and ReportId already present
$query = "DeviceProcessEvents | project Timestamp, ReportId, DeviceName"
$adapted = Convert-KqlForXdr -Query $query
Assert-NotContains -Haystack $adapted -Needle "| extend" `
    -Message "No extend needed when columns already present"

# Required columns: missing ReportId
$adapted = Convert-KqlForXdr -Query "DeviceProcessEvents | where Timestamp > ago(1h)"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added when missing"

# Required columns: missing both
$adapted = Convert-KqlForXdr -Query "DeviceNetworkEvents | where RemoteUrl has 'evil.com'"
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp added when missing"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added when missing"

# Extend existing project statement
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| project DeviceName, FileName
"@
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp added to existing project"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added to existing project"

# Preserves query logic with complex filters
$complexQuery = @"
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in ('cmd.exe', 'powershell.exe')
| summarize count() by DeviceName, FileName
| where count_ > 10
"@
$adapted = Convert-KqlForXdr -Query $complexQuery
Assert-Contains -Haystack $adapted -Needle "summarize count()" `
    -Message "Complex query logic preserved"
Assert-Contains -Haystack $adapted -Needle "where count_ > 10" `
    -Message "Post-summarize filter preserved"
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated removed from complex query"

# ============================================================================
# TEST: ConvertTo-XdrFrequency
# ============================================================================
Write-TestSection "ConvertTo-XdrFrequency"

# Direct mappings
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT5M") `
    -Message "PT5M -> PT1H"
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT10M") `
    -Message "PT10M -> PT1H"
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT15M") `
    -Message "PT15M -> PT1H"
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT30M") `
    -Message "PT30M -> PT1H"
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT1H") `
    -Message "PT1H -> PT1H"
Assert-Equal -Expected "PT3H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT2H") `
    -Message "PT2H -> PT3H"
Assert-Equal -Expected "PT3H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT3H") `
    -Message "PT3H -> PT3H"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT4H") `
    -Message "PT4H -> PT12H"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT6H") `
    -Message "PT6H -> PT12H"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT12H") `
    -Message "PT12H -> PT12H"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT24H") `
    -Message "PT24H -> PT24H"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "P1D") `
    -Message "P1D -> PT24H"

# ISO 8601 parsing fallback
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT45M") `
    -Message "PT45M -> PT1H (parsed: 0.75h)"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT8H") `
    -Message "PT8H -> PT12H (parsed)"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "P2D") `
    -Message "P2D -> PT24H (parsed: 48h)"

# Edge cases
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "") `
    -Message "Empty -> PT24H fallback"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "INVALID") `
    -Message "Invalid -> PT24H fallback"

# Case insensitive
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "pt1h") `
    -Message "Lowercase pt1h -> PT1H"

# ============================================================================
# TEST: ConvertTo-XdrCustomDetection
# ============================================================================
Write-TestSection "ConvertTo-XdrCustomDetection"

# Build a mock Sentinel rule object
function New-MockSentinelRule {
    param(
        [string]$DisplayName = "Test Detection Rule",
        [string]$Query = "DeviceProcessEvents | where FileName == 'cmd.exe'",
        [string]$Severity = "High",
        [string]$Kind = "Scheduled",
        [array]$Tactics = @("Execution", "Persistence"),
        [array]$Techniques = @("T1059", "T1053"),
        [string]$QueryFrequency = "PT1H",
        [string]$Description = "Detects suspicious process execution.",
        [bool]$Enabled = $true
    )

    return [PSCustomObject]@{
        name       = "test-rule-id-001"
        kind       = $Kind
        properties = [PSCustomObject]@{
            displayName    = $DisplayName
            query          = $Query
            severity       = $Severity
            tactics        = $Tactics
            techniques     = $Techniques
            queryFrequency = $QueryFrequency
            description    = $Description
            enabled        = $Enabled
        }
    }
}

# --- Basic conversion ---
$mockRule = New-MockSentinelRule
$mockTables = [System.Collections.Generic.List[PSCustomObject]]::new()
$mockTables.Add([PSCustomObject]@{
    TableName   = "DeviceProcessEvents"
    ProductArea = "Microsoft Defender for Endpoint"
})

$converted = ConvertTo-XdrCustomDetection -SentinelRule $mockRule -XdrTables $mockTables

Assert-NotNull -Value $converted -Message "Basic conversion returns non-null"
Assert-Equal -Expected "[Sentinel] Test Detection Rule" -Actual $converted.DisplayName `
    -Message "Display name has prefix"
Assert-Equal -Expected "Test Detection Rule" -Actual $converted.OriginalName `
    -Message "Original name preserved"
Assert-Equal -Expected "test-rule-id-001" -Actual $converted.SentinelRuleId `
    -Message "Sentinel rule ID preserved"
Assert-Equal -Expected "high" -Actual $converted.Severity `
    -Message "Severity mapped to lowercase"
Assert-Equal -Expected "PT1H" -Actual $converted.Frequency `
    -Message "Frequency mapped correctly"
Assert-Equal -Expected "Every hour" -Actual $converted.FrequencyLabel `
    -Message "Frequency label correct"
Assert-Equal -Expected "execution" -Actual $converted.AlertCategory `
    -Message "Alert category from first MITRE tactic"
Assert-Contains -Haystack ($converted.MitreTactics -join ",") -Needle "execution" `
    -Message "MITRE tactics mapped: execution"
Assert-Contains -Haystack ($converted.MitreTactics -join ",") -Needle "persistence" `
    -Message "MITRE tactics mapped: persistence"
Assert-ArrayContains -Array $converted.MitreTechniques -Value "T1059" -Message "MITRE techniques preserved"
Assert-Contains -Haystack $converted.Description -Needle "[Auto-converted from Sentinel analytic rule" `
    -Message "Description includes provenance"
Assert-Contains -Haystack $converted.QueryText -Needle "FileName" `
    -Message "Adapted query preserves detection logic"

# --- NRT rule gets PT1H frequency ---
$nrtRule = New-MockSentinelRule -Kind "NRT" -QueryFrequency ""
$converted = ConvertTo-XdrCustomDetection -SentinelRule $nrtRule -XdrTables $mockTables

Assert-NotNull -Value $converted -Message "NRT rule converts"
Assert-Equal -Expected "PT1H" -Actual $converted.Frequency `
    -Message "NRT rule -> PT1H frequency"
Assert-Equal -Expected "NRT" -Actual $converted.RuleKind `
    -Message "RuleKind is NRT"

# --- Custom prefix ---
$converted = ConvertTo-XdrCustomDetection -SentinelRule $mockRule -XdrTables $mockTables -Prefix "[Custom] "
Assert-True -Condition $converted.DisplayName.StartsWith("[Custom] ") `
    -Message "Custom prefix applied"

# --- Long display name truncation ---
$longNameRule = New-MockSentinelRule -DisplayName ("A" * 260)
$converted = ConvertTo-XdrCustomDetection -SentinelRule $longNameRule -XdrTables $mockTables
Assert-True -Condition ($converted.DisplayName.Length -le 256) `
    -Message "Display name truncated to 256 chars (got $($converted.DisplayName.Length))"
Assert-True -Condition $converted.DisplayName.EndsWith("...") `
    -Message "Truncated name ends with ..."

# --- Exposure Management only -> returns null ---
$exposureTables = [System.Collections.Generic.List[PSCustomObject]]::new()
$exposureTables.Add([PSCustomObject]@{
    TableName   = "ExposureGraphEdges"
    ProductArea = "Microsoft Security Exposure Management"
})
$exposureRule = New-MockSentinelRule -Query "ExposureGraphEdges | where SourceNodeLabel == 'device'"
$converted = ConvertTo-XdrCustomDetection -SentinelRule $exposureRule -XdrTables $exposureTables
Assert-Null -Value $converted `
    -Message "Exposure Management only rule returns null"

# --- Mixed tables: Exposure + Endpoint -> succeeds ---
$mixedTables = [System.Collections.Generic.List[PSCustomObject]]::new()
$mixedTables.Add([PSCustomObject]@{
    TableName   = "DeviceEvents"
    ProductArea = "Microsoft Defender for Endpoint"
})
$mixedTables.Add([PSCustomObject]@{
    TableName   = "ExposureGraphEdges"
    ProductArea = "Microsoft Security Exposure Management"
})
$converted = ConvertTo-XdrCustomDetection -SentinelRule $mockRule -XdrTables $mixedTables
Assert-NotNull -Value $converted -Message "Mixed tables (Endpoint + Exposure) converts"
Assert-ArrayContains -Array $converted.XdrTables -Value "DeviceEvents" `
    -Message "Compatible table included"
Assert-True -Condition ($converted.XdrTables -notcontains "ExposureGraphEdges") `
    -Message "Exposure table excluded from result"

# --- Severity mapping ---
foreach ($sev in @("Informational","Low","Medium","High")) {
    $sevRule = New-MockSentinelRule -Severity $sev
    $converted = ConvertTo-XdrCustomDetection -SentinelRule $sevRule -XdrTables $mockTables
    Assert-Equal -Expected $sev.ToLower() -Actual $converted.Severity `
        -Message "Severity '$sev' maps to '$($sev.ToLower())'"
}

# --- No tactics -> General category ---
$noTacticRule = New-MockSentinelRule -Tactics @() -Techniques @()
$converted = ConvertTo-XdrCustomDetection -SentinelRule $noTacticRule -XdrTables $mockTables
Assert-Equal -Expected "General" -Actual $converted.AlertCategory `
    -Message "No tactics -> 'General' alert category"

# --- All MITRE tactics map correctly ---
$allTacticsInput = @(
    "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation",
    "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "Exfiltration", "CommandAndControl", "Impact",
    "Reconnaissance", "ResourceDevelopment"
)
$allTacticsExpected = @(
    "initialAccess", "execution", "persistence", "privilegeEscalation",
    "defenseEvasion", "credentialAccess", "discovery", "lateralMovement",
    "collection", "exfiltration", "commandAndControl", "impact",
    "reconnaissance", "resourceDevelopment"
)
$tacticRule = New-MockSentinelRule -Tactics $allTacticsInput
$converted = ConvertTo-XdrCustomDetection -SentinelRule $tacticRule -XdrTables $mockTables
for ($i = 0; $i -lt $allTacticsExpected.Count; $i++) {
    Assert-ArrayContains -Array $converted.MitreTactics -Value $allTacticsExpected[$i] `
        -Message "Tactic '$($allTacticsInput[$i])' -> '$($allTacticsExpected[$i])'"
}

# ============================================================================
# TEST: Convert-KqlForXdr - edge cases
# ============================================================================
Write-TestSection "Convert-KqlForXdr - Edge Cases"

# Multiple TimeGenerated filters
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where TimeGenerated < ago(5m)
| where FileName == 'cmd.exe'
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "Multiple TimeGenerated filters all removed"

# TimeGenerated with different operators
$adapted = Convert-KqlForXdr -Query "DeviceEvents | where TimeGenerated >= ago(7d)"
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated with >= removed"

# Already has Timestamp (not TimeGenerated) - should not double-add
$adapted = Convert-KqlForXdr -Query "DeviceProcessEvents | project Timestamp, DeviceName, ReportId"
Assert-NotContains -Haystack $adapted -Needle "| extend" `
    -Message "No extend when both Timestamp and ReportId already present"

# Query with only Timestamp present, missing ReportId
$adapted = Convert-KqlForXdr -Query "DeviceProcessEvents | where Timestamp > ago(1h)"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added when only Timestamp present"

# ============================================================================
# TEST: Frequency and Severity Maps Completeness
# ============================================================================
Write-TestSection "Map Completeness"

# All frequency map entries are valid XDR frequencies
$validFrequencies = @("PT1H", "PT3H", "PT12H", "PT24H")
foreach ($key in $FrequencyMap.Keys) {
    Assert-ArrayContains -Array $validFrequencies -Value $FrequencyMap[$key] `
        -Message "FrequencyMap[$key] = $($FrequencyMap[$key]) is valid"
}

# All frequency display map entries exist
foreach ($freq in $validFrequencies) {
    Assert-NotNull -Value $FrequencyDisplayMap[$freq] `
        -Message "FrequencyDisplayMap has entry for $freq"
}

# All Sentinel severity values map
foreach ($sev in @("Informational","Low","Medium","High")) {
    Assert-NotNull -Value $SeverityMap[$sev] `
        -Message "SeverityMap has entry for '$sev'"
}

# All standard MITRE tactics map
foreach ($tactic in $allTacticsInput) {
    Assert-NotNull -Value $TacticMap[$tactic] `
        -Message "TacticMap has entry for '$tactic'"
}

# ============================================================================
# TEST: Find-XdrTablesInQuery - Advanced Edge Cases
# ============================================================================
Write-TestSection "Find-XdrTablesInQuery - Advanced"

# Verify comment-stripping: table in comment should NOT be found
$result = Find-XdrTablesInQuery -Query @"
// DeviceProcessEvents - commenting out this line
DeviceNetworkEvents
| where RemoteUrl has "malicious.com"
"@
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-False -Condition ($tableNames -contains "DeviceProcessEvents") `
    -Message "Table in single-line comment not detected"
Assert-True -Condition ($tableNames -contains "DeviceNetworkEvents") `
    -Message "Table in active code IS detected"

# Table name inside a string literal — word boundary still matches
# (this is a known limitation; document the behavior)
$result = Find-XdrTablesInQuery -Query @"
DeviceProcessEvents
| where ActionType == 'SomeAction'
| extend note = 'see also DeviceFileEvents documentation'
"@
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-ArrayContains -Array $tableNames -Value "DeviceProcessEvents" `
    -Message "Real table reference detected alongside string containing table name"

# Query with only comments (all lines)
$result = Find-XdrTablesInQuery -Query @"
// DeviceProcessEvents
// DeviceFileEvents
// DeviceNetworkEvents
"@
Assert-Equal -Expected 0 -Actual @($result).Count `
    -Message "All-comment query returns empty"

# Query with let statement + table
$result = Find-XdrTablesInQuery -Query @"
let threshold = 5;
let lookback = ago(24h);
EmailEvents
| where Timestamp > lookback
| summarize count() by SenderFromAddress
| where count_ > threshold
"@
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-ArrayContains -Array $tableNames -Value "EmailEvents" `
    -Message "Table detected after let statement"
Assert-Equal -Expected 1 -Actual @($result).Count `
    -Message "Only one table found (let vars not confused for tables)"

# Query with multiple identical table references — deduplication
$result = Find-XdrTablesInQuery -Query @"
DeviceProcessEvents
| union DeviceProcessEvents
| where FileName == 'cmd.exe'
"@
Assert-Equal -Expected 1 -Actual @($result).Count `
    -Message "Duplicate table references deduplicated"

# Every product area has at least one table in registry
$productAreas = @(
    "Microsoft Defender for Endpoint",
    "Microsoft Defender for Office 365",
    "Microsoft Defender for Identity",
    "Microsoft Defender for Cloud Apps",
    "Microsoft Defender XDR",
    "Microsoft Entra ID",
    "Microsoft Security Exposure Management"
)
foreach ($pa in $productAreas) {
    $tablesForArea = @($XdrTableRegistry.GetEnumerator() | Where-Object { $_.Value -eq $pa })
    Assert-True -Condition ($tablesForArea.Count -gt 0) `
        -Message "Product area '$pa' has at least one table"
}

# Query with nested subqueries (parenthesized)
$result = Find-XdrTablesInQuery -Query @"
DeviceLogonEvents
| where LogonType == "Interactive"
| join kind=leftouter (
    IdentityLogonEvents
    | where Application == "Active Directory"
    | project AccountUpn, LogonType
) on `$left.AccountName == `$right.AccountUpn
"@
$tableNames = $result | ForEach-Object { $_.TableName }
Assert-ArrayContains -Array $tableNames -Value "DeviceLogonEvents" `
    -Message "Outer table in nested query"
Assert-ArrayContains -Array $tableNames -Value "IdentityLogonEvents" `
    -Message "Inner table in nested subquery"

# ============================================================================
# TEST: Convert-KqlForXdr - Advanced Edge Cases
# ============================================================================
Write-TestSection "Convert-KqlForXdr - Advanced"

# TimeGenerated first in compound 'and' filter
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where TimeGenerated > ago(1h) and FileName == 'cmd.exe'
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated removed from compound 'and' filter (first position)"
Assert-Contains -Haystack $adapted -Needle "FileName" `
    -Message "Other condition preserved in compound filter"
Assert-NotContains -Haystack ($adapted -split "`n" | Where-Object { $_.Trim().StartsWith("and ") }) -Needle "and" `
    -Message "No orphaned 'and' at start of line"

# TimeGenerated last in compound 'and' filter
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where FileName == 'cmd.exe' and TimeGenerated > ago(1h)
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated removed from compound 'and' filter (last position)"
Assert-Contains -Haystack $adapted -Needle "FileName" `
    -Message "Other condition preserved when TimeGenerated is last"

# TimeGenerated with 'between' operator
$adapted = Convert-KqlForXdr -Query @"
DeviceEvents
| where TimeGenerated between (ago(24h) .. ago(1h))
"@
# The between pattern is different from > ago(), the regex may not catch it
# but TimeGenerated should be replaced with Timestamp at minimum
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated replaced in between clause"

# ingestion_time() with <= operator
$adapted = Convert-KqlForXdr -Query @"
DeviceNetworkEvents
| where ingestion_time() <= ago(1h)
| where RemoteUrl has "evil.com"
"@
Assert-NotContains -Haystack $adapted -Needle "ingestion_time" `
    -Message "ingestion_time with <= removed"
Assert-Contains -Haystack $adapted -Needle "RemoteUrl" `
    -Message "Detection logic preserved after ingestion_time removal"

# Query with no pipe operators at all
$adapted = Convert-KqlForXdr -Query "DeviceProcessEvents"
Assert-Contains -Haystack $adapted -Needle "DeviceProcessEvents" `
    -Message "Simple table-only query preserved"
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp added to simple query"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added to simple query"

# Query with project-keep (should be treated like project)
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| project-keep DeviceName, FileName
"@
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp added to project-keep"
Assert-Contains -Haystack $adapted -Needle "ReportId" `
    -Message "ReportId added to project-keep"

# TimeGenerated in project should become Timestamp
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where FileName == 'cmd.exe'
| project TimeGenerated, DeviceName, FileName
"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated replaced in project clause"
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp present in project clause"

# project followed by order by — ReportId should go into project, not order by
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| where FileName == 'cmd.exe'
| project Timestamp, DeviceName, FileName
| order by Timestamp desc
"@
Assert-Contains -Haystack $adapted -Needle "| project Timestamp, DeviceName, FileName, ReportId" `
    -Message "ReportId added to project, not order by"
Assert-NotContains -Haystack $adapted -Needle "order by Timestamp desc, ReportId" `
    -Message "order by clause not polluted with ReportId"

# project followed by more pipe operators
$adapted = Convert-KqlForXdr -Query @"
DeviceProcessEvents
| project DeviceName, FileName
| summarize count() by DeviceName
"@
Assert-Contains -Haystack $adapted -Needle "summarize count()" `
    -Message "Subsequent summarize preserved after project fix"
Assert-Contains -Haystack $adapted -Needle "Timestamp" `
    -Message "Timestamp added to project before summarize"

# Whitespace-heavy query
$adapted = Convert-KqlForXdr -Query @"

  DeviceProcessEvents

  |   where   TimeGenerated   >   ago(1h)

  |   where   FileName   ==   'cmd.exe'

"@
Assert-NotContains -Haystack $adapted -Needle "TimeGenerated" `
    -Message "TimeGenerated removed even with extra whitespace"
Assert-Contains -Haystack $adapted -Needle "FileName" `
    -Message "Logic preserved in whitespace-heavy query"

# ============================================================================
# TEST: ConvertTo-XdrCustomDetection - Advanced Edge Cases
# ============================================================================
Write-TestSection "ConvertTo-XdrCustomDetection - Advanced"

# Null description
$nullDescRule = New-MockSentinelRule -Description ""
$converted = ConvertTo-XdrCustomDetection -SentinelRule $nullDescRule -XdrTables $mockTables
Assert-NotNull -Value $converted -Message "Null description rule converts"
Assert-Contains -Haystack $converted.Description -Needle "[Auto-converted from Sentinel analytic rule" `
    -Message "Provenance added even with empty description"

# Empty prefix
$converted = ConvertTo-XdrCustomDetection -SentinelRule $mockRule -XdrTables $mockTables -Prefix ""
Assert-Equal -Expected "Test Detection Rule" -Actual $converted.DisplayName `
    -Message "Empty prefix means no prefix on display name"

# Multiple product areas in output
$multiTables = [System.Collections.Generic.List[PSCustomObject]]::new()
$multiTables.Add([PSCustomObject]@{ TableName = "DeviceProcessEvents"; ProductArea = "Microsoft Defender for Endpoint" })
$multiTables.Add([PSCustomObject]@{ TableName = "EmailEvents"; ProductArea = "Microsoft Defender for Office 365" })
$multiTables.Add([PSCustomObject]@{ TableName = "IdentityLogonEvents"; ProductArea = "Microsoft Defender for Identity" })

$multiRule = New-MockSentinelRule -Query @"
DeviceProcessEvents
| union EmailEvents, IdentityLogonEvents
| where Timestamp > ago(1h)
"@
$converted = ConvertTo-XdrCustomDetection -SentinelRule $multiRule -XdrTables $multiTables
Assert-NotNull -Value $converted -Message "Multi-product-area rule converts"
Assert-True -Condition ($converted.XdrTables.Count -ge 3) `
    -Message "All 3 tables present (got $($converted.XdrTables.Count))"
Assert-True -Condition ($converted.ProductAreas.Count -ge 3) `
    -Message "All 3 product areas present (got $($converted.ProductAreas.Count))"

# Unknown severity defaults to medium
$unknownSevRule = New-MockSentinelRule -Severity "Critical"
$converted = ConvertTo-XdrCustomDetection -SentinelRule $unknownSevRule -XdrTables $mockTables
Assert-Equal -Expected "medium" -Actual $converted.Severity `
    -Message "Unknown severity 'Critical' defaults to 'medium'"

# Verify output object has all expected properties
$expectedProps = @(
    "DisplayName", "OriginalName", "SentinelRuleId", "RuleKind",
    "QueryText", "OriginalQuery", "Frequency", "FrequencyLabel",
    "Severity", "MitreTactics", "MitreTechniques", "Description",
    "AlertCategory", "XdrTables", "ProductAreas", "RecommendedActions"
)
$converted = ConvertTo-XdrCustomDetection -SentinelRule $mockRule -XdrTables $mockTables
$actualProps = @($converted.PSObject.Properties.Name)
foreach ($prop in $expectedProps) {
    Assert-ArrayContains -Array $actualProps -Value $prop `
        -Message "Output has property '$prop'"
}

# Verify original query is preserved unmodified
$originalQuery = "DeviceProcessEvents | where FileName == 'cmd.exe'"
$ruleForOriginal = New-MockSentinelRule -Query $originalQuery
$converted = ConvertTo-XdrCustomDetection -SentinelRule $ruleForOriginal -XdrTables $mockTables
Assert-Equal -Expected $originalQuery -Actual $converted.OriginalQuery `
    -Message "OriginalQuery preserved unmodified"

# RecommendedActions is populated
Assert-True -Condition ($converted.RecommendedActions.Length -gt 0) `
    -Message "RecommendedActions is non-empty"

# ============================================================================
# TEST: ConvertTo-XdrFrequency - Boundary Precision
# ============================================================================
Write-TestSection "ConvertTo-XdrFrequency - Boundaries"

# Exactly at boundary values
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT60M") `
    -Message "PT60M (exactly 1h) -> PT1H"
Assert-Equal -Expected "PT3H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT61M") `
    -Message "PT61M (just over 1h) -> PT3H"
Assert-Equal -Expected "PT3H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT180M") `
    -Message "PT180M (exactly 3h) -> PT3H"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT181M") `
    -Message "PT181M (just over 3h) -> PT12H"
Assert-Equal -Expected "PT12H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT720M") `
    -Message "PT720M (exactly 12h) -> PT12H"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT721M") `
    -Message "PT721M (just over 12h) -> PT24H"

# Days + hours combination
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "P1DT2H") `
    -Message "P1DT2H (26h) -> PT24H"
Assert-Equal -Expected "PT24H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "P7D") `
    -Message "P7D (168h) -> PT24H"

# Zero duration
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT0M") `
    -Message "PT0M (0h) -> PT1H"
Assert-Equal -Expected "PT1H" -Actual (ConvertTo-XdrFrequency -SentinelFrequency "PT0H") `
    -Message "PT0H (0h) -> PT1H"

# ============================================================================
# TEST: Registry Integrity Cross-Checks
# ============================================================================
Write-TestSection "Registry Integrity Cross-Checks"

# Every table in the registry has a case-insensitive lookup entry
foreach ($tableName in $XdrTableRegistry.Keys) {
    $canonical = $XdrTableLookup[$tableName.ToLower()]
    Assert-Equal -Expected $tableName -Actual $canonical `
        -Message "XdrTableLookup[$($tableName.ToLower())] -> $tableName"
}

# Lookup table size matches registry size
Assert-Equal -Expected $XdrTableRegistry.Count -Actual $XdrTableLookup.Count `
    -Message "Lookup table size matches registry ($($XdrTableRegistry.Count))"

# Exposure Management tables are a subset of the registry
foreach ($emTable in $ExposureManagementTables) {
    Assert-True -Condition $XdrTableRegistry.ContainsKey($emTable) `
        -Message "Exposure table '$emTable' exists in main registry"
    Assert-Equal -Expected "Microsoft Security Exposure Management" `
        -Actual $XdrTableRegistry[$emTable] `
        -Message "Exposure table '$emTable' has correct product area"
}

# TacticMap values are all lowercase-first-letter-of-each-word (camelCase)
foreach ($key in $TacticMap.Keys) {
    $value = $TacticMap[$key]
    Assert-True -Condition ($value[0] -cmatch '[a-z]') `
        -Message "TacticMap[$key] starts with lowercase: '$value'"
}

# ============================================================================
# TEST: Script Structural Integrity
# ============================================================================
Write-TestSection "Script Structural Integrity"

# Verify the main script has the expected section markers
$mainScript = Get-Content -Path (Join-Path $PSScriptRoot "Check-SentinelXdrTables.ps1") -Raw
Assert-Contains -Haystack $mainScript -Needle "# CONSTANTS & REGISTRIES" `
    -Message "Has CONSTANTS & REGISTRIES section"
Assert-Contains -Haystack $mainScript -Needle "# FUNCTIONS" `
    -Message "Has FUNCTIONS section"
Assert-Contains -Haystack $mainScript -Needle "# MAIN SCRIPT" `
    -Message "Has MAIN SCRIPT section"
Assert-Contains -Haystack $mainScript -Needle "[CmdletBinding()]" `
    -Message "Has CmdletBinding attribute"
Assert-Contains -Haystack $mainScript -Needle 'Set-StrictMode -Version Latest' `
    -Message "Uses Set-StrictMode"
Assert-Contains -Haystack $mainScript -Needle '$ErrorActionPreference = "Stop"' `
    -Message "Uses Stop error action preference"

# Verify parameter declarations exist
Assert-Contains -Haystack $mainScript -Needle "SubscriptionId" `
    -Message "Has SubscriptionId parameter"
Assert-Contains -Haystack $mainScript -Needle "ResourceGroupName" `
    -Message "Has ResourceGroupName parameter"
Assert-Contains -Haystack $mainScript -Needle "WorkspaceName" `
    -Message "Has WorkspaceName parameter"
Assert-Contains -Haystack $mainScript -Needle "Translate" `
    -Message "Has Translate parameter"
Assert-Contains -Haystack $mainScript -Needle "Deploy" `
    -Message "Has Deploy parameter"

# Verify API version is recent
Assert-Contains -Haystack $mainScript -Needle "2024-09-01" `
    -Message "Uses recent Sentinel API version (2024-09-01)"

# Verify Graph API endpoint
Assert-Contains -Haystack $mainScript -Needle "graph.microsoft.com/v1.0/security/rules/detectionRules" `
    -Message "Uses correct Graph API endpoint for detection rules"

# ============================================================================
# RESULTS
# ============================================================================
Write-Host ""
Write-Host "======================================================================" -ForegroundColor $(if ($script:FailCount -eq 0) { "Green" } else { "Red" })
Write-Host "  TEST RESULTS" -ForegroundColor $(if ($script:FailCount -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor $(if ($script:FailCount -eq 0) { "Green" } else { "Red" })
Write-Host ""
Write-Host "  Total:  $($script:TestCount)" -ForegroundColor White
Write-Host "  Passed: $($script:PassCount)" -ForegroundColor Green
Write-Host "  Failed: $($script:FailCount)" -ForegroundColor $(if ($script:FailCount -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($script:FailCount -gt 0) {
    Write-Host "  FAILURES:" -ForegroundColor Red
    foreach ($detail in $script:FailDetails) {
        Write-Host $detail -ForegroundColor Red
    }
    Write-Host ""
    exit 1
}

Write-Host "  All tests passed." -ForegroundColor Green
Write-Host ""
exit 0

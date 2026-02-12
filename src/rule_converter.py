"""
Converts Sentinel analytic rules to Defender XDR custom detection rules.

Handles the mapping of Sentinel rule properties to their Defender XDR
custom detection equivalents, including frequency mapping, severity,
MITRE tactics/techniques, and KQL query adaptation.
"""

import logging
import re

from .defender_client import (
    SEVERITY_MAP,
    TACTIC_MAP,
    CustomDetectionRule,
    DetectionFrequency,
)
from .kql_parser import extract_table_references, get_primary_table
from .sentinel_client import AnalyticRule
from .xdr_tables import CUSTOM_DETECTION_COMPATIBLE_TABLES, get_xdr_table

logger = logging.getLogger(__name__)

# Sentinel uses ISO 8601 durations; map to nearest XDR frequency
FREQUENCY_MAP = {
    "PT5M": DetectionFrequency.ONE_HOUR,
    "PT10M": DetectionFrequency.ONE_HOUR,
    "PT15M": DetectionFrequency.ONE_HOUR,
    "PT30M": DetectionFrequency.ONE_HOUR,
    "PT1H": DetectionFrequency.ONE_HOUR,
    "PT2H": DetectionFrequency.THREE_HOURS,
    "PT3H": DetectionFrequency.THREE_HOURS,
    "PT4H": DetectionFrequency.TWELVE_HOURS,
    "PT6H": DetectionFrequency.TWELVE_HOURS,
    "PT12H": DetectionFrequency.TWELVE_HOURS,
    "PT24H": DetectionFrequency.TWENTY_FOUR_HOURS,
    "P1D": DetectionFrequency.TWENTY_FOUR_HOURS,
}

# Required output columns for XDR custom detection queries
XDR_REQUIRED_COLUMNS = {"Timestamp", "ReportId"}

# Columns that map entities to asset types in XDR
XDR_ENTITY_COLUMNS = {
    "DeviceId": "device",
    "DeviceName": "device",
    "RemoteDeviceName": "device",
    "AccountObjectId": "user",
    "AccountSid": "user",
    "AccountUpn": "user",
    "InitiatingProcessAccountUpn": "user",
    "RecipientEmailAddress": "mailbox",
    "SenderFromAddress": "mailbox",
    "SHA1": "file",
    "SHA256": "file",
    "FileName": "file",
    "FolderPath": "file",
    "RemoteUrl": "url",
    "Url": "url",
    "ApplicationId": "app",
    "OAuthApplicationId": "app",
}


def convert_rule(
    rule: AnalyticRule,
    adapt_query: bool = True,
    prefix: str = "[Sentinel] ",
) -> CustomDetectionRule | None:
    """
    Convert a Sentinel analytic rule to a Defender XDR custom detection rule.

    Args:
        rule: The Sentinel analytic rule to convert.
        adapt_query: If True, adapt the KQL query for XDR compatibility.
        prefix: Prefix to add to the display name for traceability.

    Returns:
        A CustomDetectionRule ready for deployment, or None if the rule
        cannot be converted.
    """
    if not rule.xdr_tables:
        logger.debug(
            "Rule '%s' has no XDR tables, skipping", rule.display_name
        )
        return None

    # Verify at least one table supports custom detections
    compatible_tables = rule.xdr_tables & CUSTOM_DETECTION_COMPATIBLE_TABLES
    if not compatible_tables:
        logger.warning(
            "Rule '%s' uses XDR tables %s but none support custom detections",
            rule.display_name,
            rule.xdr_tables,
        )
        return None

    # Adapt the KQL query for XDR custom detection requirements
    query = rule.query
    if adapt_query:
        query = adapt_query_for_xdr(query, rule.primary_xdr_table)

    # Map frequency
    frequency = map_frequency(rule.query_frequency)

    # Map severity
    severity = SEVERITY_MAP.get(rule.severity, "medium")

    # Map MITRE tactics
    mitre_tactics = []
    for tactic in rule.tactics:
        mapped = TACTIC_MAP.get(tactic)
        if mapped:
            mitre_tactics.append(mapped.value)

    # Build description with provenance
    description = (
        f"{rule.description}\n\n"
        f"[Auto-converted from Sentinel analytic rule: {rule.display_name}]"
    )

    display_name = f"{prefix}{rule.display_name}"
    # Defender XDR display names have a 256-character limit
    if len(display_name) > 256:
        display_name = display_name[:253] + "..."

    return CustomDetectionRule(
        display_name=display_name,
        query_text=query,
        enabled=True,
        frequency=frequency,
        severity=severity,
        mitre_tactics=mitre_tactics,
        mitre_techniques=rule.techniques,
        description=description,
        sentinel_rule_id=rule.rule_id,
        recommended_actions=(
            "Investigate the alert in Microsoft 365 Defender. "
            "This detection was auto-converted from a Sentinel analytic rule."
        ),
    )


def adapt_query_for_xdr(
    query: str, primary_table: str | None = None
) -> str:
    """
    Adapt a Sentinel KQL query for Defender XDR custom detection compatibility.

    XDR custom detection queries must:
    1. Reference at least one advanced hunting table
    2. Project Timestamp and ReportId columns
    3. Use only tables available in the XDR advanced hunting schema

    This function ensures the query meets those requirements while
    preserving the detection logic.
    """
    adapted = query.strip()

    # Remove Sentinel-specific time filters that conflict with XDR scheduling.
    # XDR custom detections handle their own time windowing.
    adapted = _remove_sentinel_time_filters(adapted)

    # Ensure required output columns are projected
    adapted = _ensure_required_columns(adapted, primary_table)

    return adapted


def _remove_sentinel_time_filters(query: str) -> str:
    """
    Remove Sentinel-style time filters that XDR handles natively.

    Patterns like:
      | where TimeGenerated > ago(1h)
      | where TimeGenerated >= ago(1d)
      | where ingestion_time() > ago(...)
    """
    # Remove TimeGenerated filters (Sentinel uses this; XDR uses Timestamp)
    query = re.sub(
        r"\|\s*where\s+TimeGenerated\s*[><=!]+\s*ago\s*\([^)]+\)\s*",
        "",
        query,
        flags=re.IGNORECASE,
    )

    # Replace remaining TimeGenerated references with Timestamp
    query = re.sub(
        r"\bTimeGenerated\b",
        "Timestamp",
        query,
    )

    # Remove ingestion_time() filters
    query = re.sub(
        r"\|\s*where\s+ingestion_time\s*\(\s*\)\s*[><=!]+\s*ago\s*\([^)]+\)\s*",
        "",
        query,
        flags=re.IGNORECASE,
    )

    return query


def _ensure_required_columns(query: str, primary_table: str | None) -> str:
    """
    Ensure the query projects Timestamp and ReportId as required by XDR.

    If the query already has a final ``| project`` or ``| project-keep``,
    we add missing columns.  Otherwise we append a project statement.
    """
    # Check if query already references the required columns
    has_timestamp = bool(
        re.search(r"\bTimestamp\b", query, re.IGNORECASE)
    )
    has_report_id = bool(
        re.search(r"\bReportId\b", query, re.IGNORECASE)
    )

    if has_timestamp and has_report_id:
        return query

    # Build the list of columns we need to add
    missing = []
    if not has_timestamp:
        missing.append("Timestamp")
    if not has_report_id:
        missing.append("ReportId")

    # Check if query ends with a project statement we can extend
    project_match = re.search(
        r"(\|\s*project(?:-keep)?\s+)(.*?)$",
        query,
        re.IGNORECASE | re.DOTALL,
    )

    if project_match:
        # Extend the existing project statement
        existing_cols = project_match.group(2).strip()
        new_cols = ", ".join(missing)
        return (
            query[: project_match.start()]
            + project_match.group(1)
            + existing_cols
            + ", "
            + new_cols
        )

    # Append an extend + project to include required columns
    return query + "\n| extend " + ", ".join(
        f"{col} = {col}" for col in missing
    )


def map_frequency(sentinel_frequency: str) -> DetectionFrequency:
    """Map a Sentinel query frequency to the nearest XDR detection frequency."""
    mapped = FREQUENCY_MAP.get(sentinel_frequency)
    if mapped:
        return mapped

    # Parse ISO 8601 duration and pick the best match
    hours = _parse_iso_duration_hours(sentinel_frequency)
    if hours is not None:
        if hours <= 1:
            return DetectionFrequency.ONE_HOUR
        elif hours <= 3:
            return DetectionFrequency.THREE_HOURS
        elif hours <= 12:
            return DetectionFrequency.TWELVE_HOURS
        else:
            return DetectionFrequency.TWENTY_FOUR_HOURS

    logger.warning(
        "Could not map frequency '%s', defaulting to 24h",
        sentinel_frequency,
    )
    return DetectionFrequency.TWENTY_FOUR_HOURS


def _parse_iso_duration_hours(duration: str) -> float | None:
    """Parse an ISO 8601 duration string to hours."""
    match = re.match(
        r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?",
        duration,
        re.IGNORECASE,
    )
    if not match:
        return None

    days = int(match.group(1) or 0)
    hours = int(match.group(2) or 0)
    minutes = int(match.group(3) or 0)
    seconds = int(match.group(4) or 0)

    return days * 24 + hours + minutes / 60 + seconds / 3600


def batch_convert(
    rules: list[AnalyticRule],
    adapt_query: bool = True,
    prefix: str = "[Sentinel] ",
) -> list[CustomDetectionRule]:
    """
    Convert a batch of Sentinel rules to XDR custom detection rules.

    Only returns successfully converted rules (skips incompatible ones).
    """
    converted = []
    for rule in rules:
        result = convert_rule(rule, adapt_query=adapt_query, prefix=prefix)
        if result:
            converted.append(result)
        else:
            logger.debug(
                "Rule '%s' could not be converted", rule.display_name
            )

    logger.info(
        "Converted %d of %d rules to custom detections",
        len(converted),
        len(rules),
    )
    return converted

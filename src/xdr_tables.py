"""
Registry of Microsoft Defender XDR advanced hunting tables.

These tables are available in the unified Microsoft Defender XDR
advanced hunting schema and can be used in custom detection rules.
"""

# Microsoft Defender for Endpoint tables
ENDPOINT_TABLES = {
    "DeviceEvents",
    "DeviceFileEvents",
    "DeviceFileCertificateInfo",
    "DeviceImageLoadEvents",
    "DeviceInfo",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DeviceTvmCertificateInfo",
    "DeviceTvmBrowserExtensions",
    "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
}

# Microsoft Defender for Office 365 tables
EMAIL_TABLES = {
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "UrlClickEvents",
}

# Microsoft Defender for Identity tables
IDENTITY_TABLES = {
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
}

# Microsoft Defender for Cloud Apps tables
CLOUD_APP_TABLES = {
    "CloudAppEvents",
}

# Alert and incident tables
ALERT_TABLES = {
    "AlertEvidence",
    "AlertInfo",
}

# Entra ID (Azure AD) tables
ENTRA_TABLES = {
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
}

# Exposure management tables
EXPOSURE_TABLES = {
    "ExposureGraphEdges",
    "ExposureGraphNodes",
}

# All Defender XDR tables combined
ALL_XDR_TABLES = (
    ENDPOINT_TABLES
    | EMAIL_TABLES
    | IDENTITY_TABLES
    | CLOUD_APP_TABLES
    | ALERT_TABLES
    | ENTRA_TABLES
    | EXPOSURE_TABLES
)

# Case-insensitive lookup: lowercase -> canonical name
XDR_TABLE_LOOKUP = {t.lower(): t for t in ALL_XDR_TABLES}

# Tables that support the Timestamp column required for custom detections
CUSTOM_DETECTION_COMPATIBLE_TABLES = (
    ENDPOINT_TABLES
    | EMAIL_TABLES
    | IDENTITY_TABLES
    | CLOUD_APP_TABLES
    | ALERT_TABLES
    | ENTRA_TABLES
)

# Maps each table to its product area for categorization
TABLE_PRODUCT_MAP = {}
for _table in ENDPOINT_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Defender for Endpoint"
for _table in EMAIL_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Defender for Office 365"
for _table in IDENTITY_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Defender for Identity"
for _table in CLOUD_APP_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Defender for Cloud Apps"
for _table in ALERT_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Defender XDR"
for _table in ENTRA_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Entra ID"
for _table in EXPOSURE_TABLES:
    TABLE_PRODUCT_MAP[_table] = "Microsoft Security Exposure Management"


def get_xdr_table(name: str) -> str | None:
    """Return the canonical XDR table name if it exists, else None."""
    return XDR_TABLE_LOOKUP.get(name.lower())


def is_xdr_table(name: str) -> bool:
    """Check if a table name is a known Defender XDR table."""
    return name.lower() in XDR_TABLE_LOOKUP


def get_product_for_table(name: str) -> str | None:
    """Return the product area for a given XDR table name."""
    canonical = get_xdr_table(name)
    if canonical:
        return TABLE_PRODUCT_MAP.get(canonical)
    return None

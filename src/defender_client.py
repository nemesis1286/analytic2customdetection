"""
Microsoft Defender XDR client.

Creates and manages custom detection rules in Microsoft 365 Defender
via the Microsoft Graph Security API.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum

import msal
import requests

from . import config

logger = logging.getLogger(__name__)


class DetectionFrequency(str, Enum):
    """Supported custom detection rule run frequencies."""

    CONTINUOUS = "continuous"      # NRT / continuous
    ONE_HOUR = "PT1H"             # Every hour
    THREE_HOURS = "PT3H"          # Every 3 hours
    TWELVE_HOURS = "PT12H"        # Every 12 hours
    TWENTY_FOUR_HOURS = "PT24H"   # Every 24 hours


class MitreTactic(str, Enum):
    """MITRE ATT&CK tactics used in detection rules."""

    INITIAL_ACCESS = "initialAccess"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilegeEscalation"
    DEFENSE_EVASION = "defenseEvasion"
    CREDENTIAL_ACCESS = "credentialAccess"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateralMovement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "commandAndControl"
    IMPACT = "impact"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resourceDevelopment"


# Map Sentinel severity values to Defender XDR severity
SEVERITY_MAP = {
    "Informational": "informational",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
}

# Map Sentinel tactic names to Defender XDR MITRE tactic values
TACTIC_MAP = {
    "InitialAccess": MitreTactic.INITIAL_ACCESS,
    "Execution": MitreTactic.EXECUTION,
    "Persistence": MitreTactic.PERSISTENCE,
    "PrivilegeEscalation": MitreTactic.PRIVILEGE_ESCALATION,
    "DefenseEvasion": MitreTactic.DEFENSE_EVASION,
    "CredentialAccess": MitreTactic.CREDENTIAL_ACCESS,
    "Discovery": MitreTactic.DISCOVERY,
    "LateralMovement": MitreTactic.LATERAL_MOVEMENT,
    "Collection": MitreTactic.COLLECTION,
    "Exfiltration": MitreTactic.EXFILTRATION,
    "CommandAndControl": MitreTactic.COMMAND_AND_CONTROL,
    "Impact": MitreTactic.IMPACT,
    "Reconnaissance": MitreTactic.RECONNAISSANCE,
    "ResourceDevelopment": MitreTactic.RESOURCE_DEVELOPMENT,
}


@dataclass
class CustomDetectionRule:
    """Represents a Defender XDR custom detection rule to be created."""

    display_name: str
    query_text: str
    enabled: bool = True
    frequency: DetectionFrequency = DetectionFrequency.TWENTY_FOUR_HOURS
    severity: str = "medium"
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    description: str = ""
    recommended_actions: str = ""
    # Source tracking
    sentinel_rule_id: str = ""

    def to_graph_api_payload(self) -> dict:
        """Build the Microsoft Graph API request body."""
        payload = {
            "displayName": self.display_name,
            "isEnabled": self.enabled,
            "queryCondition": {
                "queryText": self.query_text,
                "lastModifiedDateTime": None,
            },
            "schedule": {
                "period": self.frequency.value,
            },
            "detectionAction": {
                "alertTemplate": {
                    "title": self.display_name,
                    "description": self.description,
                    "severity": self.severity,
                    "category": self._primary_category(),
                    "mitreTechniques": self.mitre_techniques,
                    "recommendedActions": self.recommended_actions,
                    "impactedAssets": [],
                },
                "organizationalScope": None,
                "responseActions": [],
            },
        }
        return payload

    def _primary_category(self) -> str:
        """Derive the alert category from MITRE tactics."""
        if self.mitre_tactics:
            return self.mitre_tactics[0]
        return "General"


@dataclass
class DeploymentResult:
    """Result of deploying a custom detection rule."""

    success: bool
    rule_id: str | None = None
    display_name: str = ""
    sentinel_rule_id: str = ""
    error: str | None = None


class DefenderClient:
    """Client for managing Defender XDR custom detection rules."""

    GRAPH_BASE = "https://graph.microsoft.com"

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ):
        self.tenant_id = tenant_id or config.TENANT_ID()
        self.client_id = client_id or config.CLIENT_ID()
        self.client_secret = client_secret or config.CLIENT_SECRET()
        self._access_token: str | None = None

    def _get_access_token(self) -> str:
        """Acquire an access token for Microsoft Graph API."""
        if self._access_token:
            return self._access_token

        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=authority,
            client_credential=self.client_secret,
        )
        result = app.acquire_token_for_client(scopes=[config.GRAPH_SCOPE])

        if "access_token" not in result:
            error = result.get("error_description", "Unknown error")
            raise RuntimeError(f"Failed to acquire Graph API token: {error}")

        self._access_token = result["access_token"]
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    def _custom_detection_rules_url(self) -> str:
        return (
            f"{self.GRAPH_BASE}/{config.GRAPH_API_VERSION}"
            f"/security/rules/detectionRules"
        )

    def list_custom_detection_rules(self) -> list[dict]:
        """List all existing custom detection rules."""
        rules = []
        url = self._custom_detection_rules_url()

        while url:
            response = requests.get(url, headers=self._headers(), timeout=60)
            response.raise_for_status()
            data = response.json()
            rules.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        logger.info("Found %d existing custom detection rules", len(rules))
        return rules

    def get_existing_rule_names(self) -> set[str]:
        """Get display names of all existing custom detection rules."""
        rules = self.list_custom_detection_rules()
        return {r.get("displayName", "") for r in rules}

    def create_custom_detection_rule(
        self, rule: CustomDetectionRule
    ) -> DeploymentResult:
        """
        Create a new custom detection rule in Defender XDR.

        Returns a DeploymentResult indicating success or failure.
        """
        url = self._custom_detection_rules_url()
        payload = rule.to_graph_api_payload()

        try:
            response = requests.post(
                url,
                headers=self._headers(),
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()

            rule_id = data.get("id", "")
            logger.info(
                "Created custom detection rule '%s' (id=%s)",
                rule.display_name,
                rule_id,
            )
            return DeploymentResult(
                success=True,
                rule_id=rule_id,
                display_name=rule.display_name,
                sentinel_rule_id=rule.sentinel_rule_id,
            )
        except requests.HTTPError as e:
            error_body = ""
            try:
                error_body = e.response.json().get("error", {}).get(
                    "message", str(e)
                )
            except Exception:
                error_body = str(e)

            logger.error(
                "Failed to create custom detection rule '%s': %s",
                rule.display_name,
                error_body,
            )
            return DeploymentResult(
                success=False,
                display_name=rule.display_name,
                sentinel_rule_id=rule.sentinel_rule_id,
                error=error_body,
            )

    def deploy_rules(
        self,
        rules: list[CustomDetectionRule],
        skip_existing: bool = True,
    ) -> list[DeploymentResult]:
        """
        Deploy multiple custom detection rules.

        Args:
            rules: List of custom detection rules to create.
            skip_existing: If True, skip rules whose display name already
                          exists in Defender XDR.
        """
        results: list[DeploymentResult] = []

        existing_names = set()
        if skip_existing:
            try:
                existing_names = self.get_existing_rule_names()
            except Exception as e:
                logger.warning(
                    "Could not fetch existing rules, proceeding without "
                    "duplicate check: %s",
                    e,
                )

        for rule in rules:
            if skip_existing and rule.display_name in existing_names:
                logger.info(
                    "Skipping '%s' — rule already exists", rule.display_name
                )
                results.append(
                    DeploymentResult(
                        success=True,
                        display_name=rule.display_name,
                        sentinel_rule_id=rule.sentinel_rule_id,
                        error="Skipped — rule already exists",
                    )
                )
                continue

            result = self.create_custom_detection_rule(rule)
            results.append(result)

        succeeded = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        logger.info(
            "Deployment complete: %d succeeded, %d failed", succeeded, failed
        )
        return results

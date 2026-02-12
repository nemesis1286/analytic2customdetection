"""
Microsoft Sentinel API client.

Reads analytic rules from a Sentinel workspace via the Azure Management
REST API and identifies rules whose KQL queries reference Defender XDR
tables.
"""

import logging
from dataclasses import dataclass, field

import msal
import requests

from . import config
from .kql_parser import extract_table_references, get_primary_table

logger = logging.getLogger(__name__)


@dataclass
class AnalyticRule:
    """Represents a Sentinel scheduled analytic rule."""

    rule_id: str
    name: str
    display_name: str
    description: str
    severity: str
    enabled: bool
    query: str
    query_frequency: str
    query_period: str
    trigger_operator: str
    trigger_threshold: int
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    entity_mappings: list[dict] = field(default_factory=list)
    xdr_tables: set[str] = field(default_factory=set)
    primary_xdr_table: str | None = None


class SentinelClient:
    """Client for reading Sentinel analytic rules."""

    BASE_URL = "https://management.azure.com"

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subscription_id: str | None = None,
        resource_group: str | None = None,
        workspace_name: str | None = None,
    ):
        self.tenant_id = tenant_id or config.TENANT_ID()
        self.client_id = client_id or config.CLIENT_ID()
        self.client_secret = client_secret or config.CLIENT_SECRET()
        self.subscription_id = subscription_id or config.SUBSCRIPTION_ID()
        self.resource_group = resource_group or config.RESOURCE_GROUP()
        self.workspace_name = workspace_name or config.WORKSPACE_NAME()
        self._access_token: str | None = None

    def _get_access_token(self) -> str:
        """Acquire an access token for Azure Management API via MSAL."""
        if self._access_token:
            return self._access_token

        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=authority,
            client_credential=self.client_secret,
        )
        result = app.acquire_token_for_client(scopes=[config.MANAGEMENT_SCOPE])

        if "access_token" not in result:
            error = result.get("error_description", "Unknown error")
            raise RuntimeError(
                f"Failed to acquire management API token: {error}"
            )

        self._access_token = result["access_token"]
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    def _alert_rules_url(self) -> str:
        return (
            f"{self.BASE_URL}/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights/alertRules"
            f"?api-version={config.SENTINEL_API_VERSION}"
        )

    def get_all_analytic_rules(self) -> list[AnalyticRule]:
        """
        Fetch all analytic rules from the Sentinel workspace.

        Handles pagination via nextLink.
        """
        rules: list[AnalyticRule] = []
        url = self._alert_rules_url()

        while url:
            response = requests.get(url, headers=self._headers(), timeout=60)
            response.raise_for_status()
            data = response.json()

            for item in data.get("value", []):
                rule = self._parse_rule(item)
                if rule:
                    rules.append(rule)

            url = data.get("nextLink")

        logger.info("Fetched %d analytic rules from Sentinel", len(rules))
        return rules

    def get_active_analytic_rules(self) -> list[AnalyticRule]:
        """Fetch only enabled (active) analytic rules."""
        return [r for r in self.get_all_analytic_rules() if r.enabled]

    def get_xdr_eligible_rules(self) -> list[AnalyticRule]:
        """
        Return active rules that reference Defender XDR tables.

        These are candidates for conversion to custom detection rules.
        """
        eligible = []
        for rule in self.get_active_analytic_rules():
            if rule.xdr_tables:
                eligible.append(rule)

        logger.info(
            "Found %d active rules referencing XDR tables", len(eligible)
        )
        return eligible

    def _parse_rule(self, item: dict) -> AnalyticRule | None:
        """Parse an API response item into an AnalyticRule."""
        kind = item.get("kind", "")

        # Only process Scheduled and NRT rules (they have KQL queries)
        if kind not in ("Scheduled", "NRT"):
            return None

        props = item.get("properties", {})
        query = props.get("query", "")

        # Identify XDR table references in the query
        xdr_tables = extract_table_references(query)
        primary_table = get_primary_table(query)

        return AnalyticRule(
            rule_id=item.get("name", ""),
            name=item.get("name", ""),
            display_name=props.get("displayName", ""),
            description=props.get("description", ""),
            severity=props.get("severity", "Medium"),
            enabled=props.get("enabled", False),
            query=query,
            query_frequency=props.get("queryFrequency", "PT1H"),
            query_period=props.get("queryPeriod", "PT1H"),
            trigger_operator=props.get("triggerOperator", "GreaterThan"),
            trigger_threshold=props.get("triggerThreshold", 0),
            tactics=props.get("tactics", []),
            techniques=props.get("techniques", []),
            entity_mappings=props.get("entityMappings", []),
            xdr_tables=xdr_tables,
            primary_xdr_table=primary_table,
        )

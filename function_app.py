"""
Azure Function App — HTTP endpoints for the Security Copilot plugin.

Provides three skills:
  1. ScanAnalyticRules — scan Sentinel analytic rules and identify those
     referencing Defender XDR tables.
  2. ConvertRules — convert eligible Sentinel rules to XDR custom
     detection rule payloads (dry-run preview).
  3. DeployCustomDetections — convert and deploy custom detection rules
     into Defender XDR.
"""

import json
import logging

import azure.functions as func

from src.defender_client import DefenderClient, DeploymentResult
from src.kql_parser import extract_xdr_table_references
from src.rule_converter import batch_convert, convert_rule
from src.sentinel_client import SentinelClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Skill 1: Scan Analytic Rules
# ---------------------------------------------------------------------------


@app.route(route="scan", methods=["POST"])
def scan_analytic_rules(req: func.HttpRequest) -> func.HttpResponse:
    """
    Scan all active Sentinel analytic rules and identify those that
    reference Defender XDR advanced hunting tables.

    Returns a report of eligible rules with their XDR table references.
    """
    logger.info("Scanning Sentinel analytic rules for XDR table references")

    try:
        sentinel = SentinelClient()
        active_rules = sentinel.get_active_analytic_rules()

        results = []
        for rule in active_rules:
            xdr_refs = extract_xdr_table_references(rule.query)
            if xdr_refs:
                results.append(
                    {
                        "ruleId": rule.rule_id,
                        "displayName": rule.display_name,
                        "severity": rule.severity,
                        "enabled": rule.enabled,
                        "xdrTables": [
                            {
                                "table": ref["table"],
                                "product": ref["product"],
                            }
                            for ref in xdr_refs
                        ],
                        "primaryTable": rule.primary_xdr_table,
                        "tactics": rule.tactics,
                        "techniques": rule.techniques,
                        "queryPreview": rule.query[:500],
                    }
                )

        summary = {
            "totalActiveRules": len(active_rules),
            "rulesWithXdrTables": len(results),
            "rulesWithoutXdrTables": len(active_rules) - len(results),
            "eligibleRules": results,
        }

        return func.HttpResponse(
            json.dumps(summary, indent=2),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as e:
        logger.exception("Error scanning analytic rules")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json",
        )


# ---------------------------------------------------------------------------
# Skill 2: Convert Rules (Dry Run)
# ---------------------------------------------------------------------------


@app.route(route="convert", methods=["POST"])
def convert_rules(req: func.HttpRequest) -> func.HttpResponse:
    """
    Convert eligible Sentinel analytic rules to Defender XDR custom
    detection rule format.

    This is a dry-run preview — no rules are deployed.  The response
    includes the converted rule payloads for review.

    Optional request body:
      {
        "ruleIds": ["id1", "id2"]   // only convert specific rules
        "prefix": "[Sentinel] "     // display name prefix
      }
    """
    logger.info("Converting Sentinel rules to XDR custom detections (dry run)")

    try:
        body = _parse_body(req)
        rule_ids = body.get("ruleIds")
        prefix = body.get("prefix", "[Sentinel] ")

        sentinel = SentinelClient()
        eligible_rules = sentinel.get_xdr_eligible_rules()

        # Optionally filter to specific rule IDs
        if rule_ids:
            rule_id_set = set(rule_ids)
            eligible_rules = [
                r for r in eligible_rules if r.rule_id in rule_id_set
            ]

        converted = batch_convert(
            eligible_rules, adapt_query=True, prefix=prefix
        )

        results = []
        for detection in converted:
            results.append(
                {
                    "displayName": detection.display_name,
                    "severity": detection.severity,
                    "frequency": detection.frequency.value,
                    "mitreTactics": detection.mitre_tactics,
                    "mitreTechniques": detection.mitre_techniques,
                    "sentinelRuleId": detection.sentinel_rule_id,
                    "queryText": detection.query_text,
                    "description": detection.description,
                }
            )

        summary = {
            "eligibleRulesCount": len(eligible_rules),
            "convertedCount": len(converted),
            "skippedCount": len(eligible_rules) - len(converted),
            "convertedRules": results,
        }

        return func.HttpResponse(
            json.dumps(summary, indent=2),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as e:
        logger.exception("Error converting rules")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json",
        )


# ---------------------------------------------------------------------------
# Skill 3: Deploy Custom Detections
# ---------------------------------------------------------------------------


@app.route(route="deploy", methods=["POST"])
def deploy_custom_detections(req: func.HttpRequest) -> func.HttpResponse:
    """
    Convert and deploy Sentinel analytic rules as Defender XDR custom
    detection rules.

    Optional request body:
      {
        "ruleIds": ["id1", "id2"],  // only deploy specific rules
        "prefix": "[Sentinel] ",    // display name prefix
        "skipExisting": true         // skip rules that already exist
      }
    """
    logger.info("Deploying custom detection rules to Defender XDR")

    try:
        body = _parse_body(req)
        rule_ids = body.get("ruleIds")
        prefix = body.get("prefix", "[Sentinel] ")
        skip_existing = body.get("skipExisting", True)

        # Step 1: Fetch eligible Sentinel rules
        sentinel = SentinelClient()
        eligible_rules = sentinel.get_xdr_eligible_rules()

        if rule_ids:
            rule_id_set = set(rule_ids)
            eligible_rules = [
                r for r in eligible_rules if r.rule_id in rule_id_set
            ]

        # Step 2: Convert to custom detection rules
        converted = batch_convert(
            eligible_rules, adapt_query=True, prefix=prefix
        )

        if not converted:
            return func.HttpResponse(
                json.dumps(
                    {
                        "message": "No rules eligible for conversion.",
                        "eligibleRulesScanned": len(eligible_rules),
                        "deployed": 0,
                    }
                ),
                status_code=200,
                mimetype="application/json",
            )

        # Step 3: Deploy to Defender XDR
        defender = DefenderClient()
        results = defender.deploy_rules(
            converted, skip_existing=skip_existing
        )

        deployment_report = _build_deployment_report(
            eligible_rules, converted, results
        )

        return func.HttpResponse(
            json.dumps(deployment_report, indent=2),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as e:
        logger.exception("Error deploying custom detection rules")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_body(req: func.HttpRequest) -> dict:
    """Safely parse the JSON request body."""
    try:
        return req.get_json()
    except ValueError:
        return {}


def _build_deployment_report(
    eligible_rules: list,
    converted: list,
    results: list[DeploymentResult],
) -> dict:
    """Build a structured deployment report."""
    succeeded = [r for r in results if r.success and not r.error]
    skipped = [r for r in results if r.success and r.error]
    failed = [r for r in results if not r.success]

    return {
        "summary": {
            "eligibleRulesScanned": len(eligible_rules),
            "rulesConverted": len(converted),
            "deployed": len(succeeded),
            "skipped": len(skipped),
            "failed": len(failed),
        },
        "deployed": [
            {
                "displayName": r.display_name,
                "ruleId": r.rule_id,
                "sentinelRuleId": r.sentinel_rule_id,
            }
            for r in succeeded
        ],
        "skipped": [
            {
                "displayName": r.display_name,
                "reason": r.error,
            }
            for r in skipped
        ],
        "failed": [
            {
                "displayName": r.display_name,
                "sentinelRuleId": r.sentinel_rule_id,
                "error": r.error,
            }
            for r in failed
        ],
    }

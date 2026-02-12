# Sentinel Analytic to XDR Custom Detection

A Microsoft Security Copilot plugin that scans active Microsoft Sentinel analytic rules, identifies those referencing Defender XDR advanced hunting tables, and deploys equivalent custom detection rules into Microsoft 365 Defender.

## Why

Organizations running both Microsoft Sentinel and Defender XDR often have analytic rules in Sentinel whose KQL queries already target Defender XDR tables (`DeviceEvents`, `EmailEvents`, `IdentityLogonEvents`, etc.). These rules can run natively as XDR custom detection rules, giving you faster detection times and built-in response actions (device isolation, investigation packages, etc.) without maintaining duplicate logic by hand.

This agent automates that bridge.

## How It Works

```
Sentinel Workspace                        Defender XDR
┌──────────────────────┐                  ┌──────────────────────┐
│  Analytic Rules      │                  │  Custom Detection    │
│                      │   scan/convert   │  Rules               │
│  Rule A (Syslog)     │ ──────────────>  │                      │
│  Rule B (DeviceEvents│ ── eligible ──>  │  [Sentinel] Rule B   │
│  Rule C (EmailEvents)│ ── eligible ──>  │  [Sentinel] Rule C   │
│  Rule D (AzureAD)    │                  │                      │
└──────────────────────┘                  └──────────────────────┘
```

1. **Scan** — Reads all active Sentinel analytic rules via the Azure Management API and parses each KQL query to find references to any of the 45+ known Defender XDR tables.
2. **Convert** — Transforms eligible rules into the XDR custom detection format:
   - Replaces `TimeGenerated` with `Timestamp`
   - Removes Sentinel-specific time-window filters (XDR handles scheduling natively)
   - Ensures queries project `Timestamp` and `ReportId` (required by XDR)
   - Maps Sentinel frequencies to XDR-supported intervals (1h, 3h, 12h, 24h)
   - Translates MITRE ATT&CK tactic names to the Graph API format
   - Prefixes rule names with `[Sentinel]` for traceability
3. **Deploy** — Creates the custom detection rules in Defender XDR via the Microsoft Graph Security API, skipping any that already exist.

## Security Copilot Skills

Once the plugin is installed in the Security Copilot store, three skills become available:

| Skill | Description | Example Prompt |
|-------|-------------|----------------|
| **ScanAnalyticRules** | Identify which Sentinel rules reference XDR tables | *"Scan my Sentinel analytic rules for Defender XDR table references"* |
| **ConvertRules** | Dry-run preview of converted custom detection payloads | *"Preview the XDR custom detection rules that would be created"* |
| **DeployCustomDetections** | Convert and deploy rules into Defender XDR | *"Deploy Sentinel analytics as XDR custom detections"* |

## Supported XDR Tables

The agent recognizes tables across the full Defender XDR advanced hunting schema:

| Product | Tables |
|---------|--------|
| Defender for Endpoint | `DeviceEvents`, `DeviceFileEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceImageLoadEvents`, `DeviceInfo`, `DeviceNetworkInfo`, `DeviceFileCertificateInfo`, and TVM tables |
| Defender for Office 365 | `EmailEvents`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `UrlClickEvents` |
| Defender for Identity | `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents` |
| Defender for Cloud Apps | `CloudAppEvents` |
| Microsoft Entra ID | `AADSignInEventsBeta`, `AADSpnSignInEventsBeta` |
| XDR Alerts | `AlertInfo`, `AlertEvidence` |
| Exposure Management | `ExposureGraphEdges`, `ExposureGraphNodes` |

## Project Structure

```
analytic2customdetection/
├── manifest.yaml               # Security Copilot plugin manifest
├── openapi.yaml                # OpenAPI 3.0 spec for the API
├── function_app.py             # Azure Function HTTP endpoints
├── host.json                   # Azure Functions host configuration
├── requirements.txt            # Python dependencies
├── local.settings.example.json # Environment variable template
└── src/
    ├── config.py               # Configuration from environment variables
    ├── xdr_tables.py           # Registry of 45+ Defender XDR tables
    ├── kql_parser.py           # KQL parser for table reference extraction
    ├── sentinel_client.py      # Sentinel API client (read analytic rules)
    ├── defender_client.py      # Defender XDR client (create custom detections)
    └── rule_converter.py       # Sentinel rule → XDR custom detection converter
```

## Prerequisites

- **Azure subscription** with a Sentinel workspace containing active analytic rules
- **Microsoft 365 Defender** (Defender XDR) tenant
- **App registration** in Entra ID with the following API permissions:
  - `Microsoft Graph` > `CustomDetection.ReadWrite.All`
  - `Microsoft Graph` > `ThreatHunting.Read.All`
  - `Azure Service Management` > `user_impersonation` (or use application permissions with `Microsoft.SecurityInsights/alertRules/read`)
- **Azure Functions Core Tools** (for local development)
- **Python 3.10+**

## Setup

### 1. Clone and configure

```bash
git clone <repo-url>
cd analytic2customdetection
cp local.settings.example.json local.settings.json
```

Edit `local.settings.json` with your environment values:

```json
{
  "Values": {
    "AZURE_TENANT_ID": "<your-tenant-id>",
    "AZURE_CLIENT_ID": "<your-client-id>",
    "AZURE_CLIENT_SECRET": "<your-client-secret>",
    "AZURE_SUBSCRIPTION_ID": "<your-subscription-id>",
    "SENTINEL_RESOURCE_GROUP": "<your-resource-group>",
    "SENTINEL_WORKSPACE_NAME": "<your-workspace-name>"
  }
}
```

### 2. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Run locally

```bash
func start
```

The three endpoints will be available at:
- `POST http://localhost:7071/api/scan`
- `POST http://localhost:7071/api/convert`
- `POST http://localhost:7071/api/deploy`

### 4. Deploy to Azure

```bash
func azure functionapp publish <your-function-app-name>
```

### 5. Register in Security Copilot

1. Go to **Security Copilot** > **Plugin management** > **Add plugin**
2. Upload `manifest.yaml` (update the `{{FUNCTION_APP_NAME}}`, `{{AZURE_CLIENT_ID}}`, and `{{AZURE_TENANT_ID}}` placeholders first)
3. The three skills will appear in the Security Copilot skill catalog

## API Usage

### Scan rules

```bash
curl -X POST https://<function-app>.azurewebsites.net/api/scan \
  -H "x-functions-key: <your-function-key>"
```

### Convert rules (dry run)

```bash
curl -X POST https://<function-app>.azurewebsites.net/api/convert \
  -H "Content-Type: application/json" \
  -H "x-functions-key: <your-function-key>" \
  -d '{"prefix": "[Sentinel] "}'
```

### Deploy rules

```bash
curl -X POST https://<function-app>.azurewebsites.net/api/deploy \
  -H "Content-Type: application/json" \
  -H "x-functions-key: <your-function-key>" \
  -d '{"skipExisting": true}'
```

Optionally pass `ruleIds` to target specific Sentinel rules:

```json
{
  "ruleIds": ["rule-guid-1", "rule-guid-2"],
  "skipExisting": true
}
```

## License

MIT

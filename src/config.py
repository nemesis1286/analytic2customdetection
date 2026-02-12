"""
Configuration management for the Analytic-to-Custom-Detection agent.

Reads settings from environment variables (populated via Azure Function
Application Settings or local.settings.json during development).
"""

import os


def get_required(name: str) -> str:
    """Get a required environment variable or raise."""
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set."
        )
    return value


def get_optional(name: str, default: str = "") -> str:
    """Get an optional environment variable with a default."""
    return os.environ.get(name, default)


# Azure AD / Entra ID credentials for authentication
TENANT_ID = lambda: get_required("AZURE_TENANT_ID")  # noqa: E731
CLIENT_ID = lambda: get_required("AZURE_CLIENT_ID")  # noqa: E731
CLIENT_SECRET = lambda: get_required("AZURE_CLIENT_SECRET")  # noqa: E731

# Sentinel workspace identifiers
SUBSCRIPTION_ID = lambda: get_required("AZURE_SUBSCRIPTION_ID")  # noqa: E731
RESOURCE_GROUP = lambda: get_required("SENTINEL_RESOURCE_GROUP")  # noqa: E731
WORKSPACE_NAME = lambda: get_required("SENTINEL_WORKSPACE_NAME")  # noqa: E731

# API versions
SENTINEL_API_VERSION = "2024-03-01"
GRAPH_API_VERSION = "v1.0"

# Microsoft Graph scopes
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MANAGEMENT_SCOPE = "https://management.azure.com/.default"

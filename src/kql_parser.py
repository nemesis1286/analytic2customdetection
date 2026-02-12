"""
KQL (Kusto Query Language) parser for extracting table references.

Identifies Defender XDR table names referenced in Sentinel analytic rule
queries so we can determine which rules are candidates for conversion to
XDR custom detection rules.
"""

import re

from .xdr_tables import ALL_XDR_TABLES, XDR_TABLE_LOOKUP, get_xdr_table


def extract_table_references(kql_query: str) -> set[str]:
    """
    Extract all table names referenced in a KQL query.

    Handles common KQL patterns:
      - Direct table references as statement starters (e.g. ``DeviceEvents``)
      - union operators (e.g. ``union DeviceEvents, DeviceFileEvents``)
      - join operators (e.g. ``join (DeviceLogonEvents | where ...)``)
      - let statements with table references
      - datatable references after pipes

    Returns canonical XDR table names found in the query.
    """
    if not kql_query:
        return set()

    found_tables: set[str] = set()
    cleaned = _strip_comments(kql_query)

    # Strategy 1: Match any known XDR table name that appears as a
    # word boundary in the query.  This is the most reliable approach
    # because KQL table names are unique enough to avoid false positives
    # when checked against the known registry.
    for table in ALL_XDR_TABLES:
        pattern = rf"\b{re.escape(table)}\b"
        if re.search(pattern, cleaned, re.IGNORECASE):
            found_tables.add(table)

    # Strategy 2: Extract table-position tokens for tables we might
    # have missed (e.g. new tables not yet in the registry).  This
    # catches the structural KQL patterns.
    structural_tables = _extract_structural_tables(cleaned)
    for token in structural_tables:
        canonical = get_xdr_table(token)
        if canonical:
            found_tables.add(canonical)

    return found_tables


def extract_xdr_table_references(kql_query: str) -> list[dict]:
    """
    Extract XDR table references with metadata.

    Returns a list of dicts with:
      - table: canonical table name
      - product: the Defender product area
      - positions: list of (start, end) char offsets in the original query
    """
    from .xdr_tables import get_product_for_table

    if not kql_query:
        return []

    results = []
    for table in extract_table_references(kql_query):
        positions = [
            (m.start(), m.end())
            for m in re.finditer(
                rf"\b{re.escape(table)}\b", kql_query, re.IGNORECASE
            )
        ]
        results.append(
            {
                "table": table,
                "product": get_product_for_table(table),
                "positions": positions,
            }
        )

    return sorted(results, key=lambda r: r["table"])


def query_uses_xdr_tables(kql_query: str) -> bool:
    """Return True if the KQL query references any Defender XDR table."""
    return len(extract_table_references(kql_query)) > 0


def get_primary_table(kql_query: str) -> str | None:
    """
    Determine the primary (first referenced) XDR table in a KQL query.

    Custom detection rules require specifying a primary table for the
    detection frequency and entity mapping.
    """
    if not kql_query:
        return None

    cleaned = _strip_comments(kql_query)
    # Walk through the query linearly and return the first XDR table found
    for match in re.finditer(r"\b([A-Z]\w+)\b", cleaned):
        token = match.group(1)
        canonical = get_xdr_table(token)
        if canonical:
            return canonical
    return None


# --- Internal helpers ---


def _strip_comments(kql: str) -> str:
    """Remove KQL comments (// line comments and /* block comments */)."""
    # Remove block comments
    kql = re.sub(r"/\*.*?\*/", " ", kql, flags=re.DOTALL)
    # Remove line comments
    kql = re.sub(r"//[^\n]*", " ", kql)
    return kql


def _extract_structural_tables(cleaned_kql: str) -> set[str]:
    """
    Extract tokens that appear in table-reference positions in KQL.

    Covers:
      - Statement-initial position (start of line / after semicolons)
      - After ``union`` keyword
      - After ``join`` / ``join kind=...`` followed by ``(``
      - After ``let ... =`` when the RHS starts with a table
    """
    tokens: set[str] = set()

    # Table at start of a statement (start of string or after ;)
    for m in re.finditer(
        r"(?:^|;\s*)([A-Za-z]\w+)", cleaned_kql, re.MULTILINE
    ):
        tokens.add(m.group(1))

    # Tables after union (comma-separated list)
    for m in re.finditer(
        r"\bunion\b[\s\w=]*\b([A-Za-z]\w+(?:\s*,\s*[A-Za-z]\w+)*)",
        cleaned_kql,
        re.IGNORECASE,
    ):
        for table_match in re.finditer(r"[A-Za-z]\w+", m.group(1)):
            tokens.add(table_match.group())

    # Tables after join (possibly with kind=inner/outer/etc.)
    for m in re.finditer(
        r"\bjoin\b(?:\s+kind\s*=\s*\w+)?\s*\(?\s*([A-Za-z]\w+)",
        cleaned_kql,
        re.IGNORECASE,
    ):
        tokens.add(m.group(1))

    # Tables in let statements: let x = TableName
    for m in re.finditer(
        r"\blet\b\s+\w+\s*=\s*([A-Za-z]\w+)", cleaned_kql, re.IGNORECASE
    ):
        tokens.add(m.group(1))

    # Filter out KQL keywords
    kql_keywords = {
        "let", "union", "join", "where", "project", "extend", "summarize",
        "sort", "order", "top", "take", "limit", "count", "distinct",
        "render", "as", "on", "by", "with", "and", "or", "not", "in",
        "has", "contains", "startswith", "endswith", "matches", "between",
        "ago", "now", "bin", "toscalar", "materialize", "datatable",
        "print", "evaluate", "invoke", "external_data", "find", "search",
        "make_series", "mv_expand", "mv_apply", "parse", "parse_json",
        "dynamic", "bool", "int", "long", "real", "string", "datetime",
        "timespan", "true", "false", "kind", "inner", "outer", "left",
        "right", "anti", "semi", "fullouter", "innerunique", "if", "iff",
        "case", "pack", "pack_all", "bag_unpack",
    }
    tokens = {t for t in tokens if t.lower() not in kql_keywords}

    return tokens

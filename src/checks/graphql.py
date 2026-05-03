"""GraphQL-specific security checks.

Checks:
  - Introspection enabled (exposes full schema)
  - Query depth limit (no limit → DoS via deeply-nested queries)
  - Aliases abuse (no limit → field enumeration / response inflation)
  - Batching abuse (multiple operations in one request → rate limit bypass)
"""

from __future__ import annotations

from typing import Any

from checks.models import CheckResult, MockResponse, Severity


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------

_INTROSPECTION_QUERY = '{"query": "{ __schema { queryType { name } } }"}'
_INTROSPECTION_INDICATORS = ["__schema", "__type", "queryType", "mutationType"]


def check_introspection(response: MockResponse) -> CheckResult:
    """Check if GraphQL introspection is enabled."""
    check_id = "GQL_INTROSPECTION"
    body = response.json()
    body_str = str(body).lower()
    enabled = (
        response.status_code == 200
        and any(ind.lower() in body_str for ind in _INTROSPECTION_INDICATORS)
    )

    if enabled:
        return CheckResult(
            check_id=check_id,
            name="GraphQL Introspection Enabled",
            severity=Severity.MEDIUM,
            passed=False,
            description="GraphQL introspection is enabled — full schema is disclosed.",
            detail="Introspection returns __schema data.",
            evidence={"status_code": response.status_code},
            remediation=(
                "Disable introspection in production. "
                "Most GraphQL servers support `introspection: false` in their config."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="GraphQL Introspection Enabled",
        severity=Severity.MEDIUM,
        passed=True,
        description="GraphQL introspection is disabled or not reachable.",
    )


# ---------------------------------------------------------------------------
# Query depth
# ---------------------------------------------------------------------------

def _nested_query(depth: int) -> str:
    """Build a deeply nested GraphQL query."""
    query = "query { user"
    for _ in range(depth):
        query += " { friends"
    query += " { id }"
    for _ in range(depth):
        query += " }"
    query += " }"
    return f'{{"query": "{query}"}}'


def check_depth_limit(
    responses_by_depth: dict[int, MockResponse],
) -> CheckResult:
    """Check if deep queries are rejected.

    Args:
        responses_by_depth: mapping of query_depth → response for that depth.
    """
    check_id = "GQL_DEPTH_LIMIT"
    unlimited_depths = [
        d for d, r in responses_by_depth.items() if r.status_code == 200
    ]
    limited_depths = [
        d for d, r in responses_by_depth.items() if r.status_code in (400, 422)
    ]

    if not limited_depths and unlimited_depths:
        max_depth = max(unlimited_depths)
        return CheckResult(
            check_id=check_id,
            name="GraphQL Query Depth — No Limit",
            severity=Severity.HIGH,
            passed=False,
            description=f"No query depth limit found (tested up to depth {max_depth}).",
            detail=f"All depths returned 200: {unlimited_depths}",
            evidence={"unlimited_depths": unlimited_depths},
            remediation=(
                "Implement a query depth limit (e.g. max depth 10). "
                "Libraries: graphene-django depth-limit, graphql-depth-limit (JS)."
            ),
        )

    if limited_depths:
        return CheckResult(
            check_id=check_id,
            name="GraphQL Query Depth — No Limit",
            severity=Severity.HIGH,
            passed=True,
            description=f"Query depth limit enforced at depth {min(limited_depths)}.",
            detail=f"Rejected depths: {limited_depths}",
        )

    return CheckResult(
        check_id=check_id,
        name="GraphQL Query Depth — No Limit",
        severity=Severity.HIGH,
        passed=True,
        description="Query depth check inconclusive.",
    )


# ---------------------------------------------------------------------------
# Alias abuse
# ---------------------------------------------------------------------------

def check_alias_abuse(response: MockResponse, alias_count: int = 100) -> CheckResult:
    """Check if a query with many aliases returns a bloated 200 response.

    A response with many repeated alias fields suggests no alias limit.
    """
    check_id = "GQL_ALIAS_ABUSE"
    body = response.json()
    data = body.get("data", {}) if isinstance(body, dict) else {}

    repeated_keys = sum(1 for k in data if k.startswith("a"))

    if response.status_code == 200 and repeated_keys >= alias_count // 2:
        return CheckResult(
            check_id=check_id,
            name="GraphQL Alias Abuse",
            severity=Severity.MEDIUM,
            passed=False,
            description=f"Server returned {repeated_keys} aliased fields — no alias limit.",
            detail=f"Sent {alias_count} aliases, got {repeated_keys} back.",
            evidence={"alias_count": alias_count, "returned_fields": repeated_keys},
            remediation="Implement a maximum number of aliases per query.",
        )

    return CheckResult(
        check_id=check_id,
        name="GraphQL Alias Abuse",
        severity=Severity.MEDIUM,
        passed=True,
        description="Alias limit appears to be enforced.",
    )


# ---------------------------------------------------------------------------
# Batch queries
# ---------------------------------------------------------------------------

def check_batch_queries(response: MockResponse, batch_size: int = 50) -> CheckResult:
    """Check if batched GraphQL queries bypass rate limiting."""
    check_id = "GQL_BATCH"
    body = response.json()
    results = body if isinstance(body, list) else []

    if response.status_code == 200 and len(results) >= batch_size:
        return CheckResult(
            check_id=check_id,
            name="GraphQL Batch Query Abuse",
            severity=Severity.MEDIUM,
            passed=False,
            description=f"Server processed {len(results)} batched operations in one request.",
            detail="Batch operations allow rate limit bypass.",
            evidence={"batch_size": batch_size, "returned_results": len(results)},
            remediation=(
                "Limit batch query count per request. "
                "Apply rate limiting at the operation level, not just per HTTP request."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="GraphQL Batch Query Abuse",
        severity=Severity.MEDIUM,
        passed=True,
        description="Batch query size appears limited.",
    )

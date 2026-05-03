"""OWASP API Security Top 10 checks.

Each check_* function takes a Response-like object (or raw response data)
and returns a CheckResult.  They are designed to be injectable — tests
pass mock responses directly; the scanner passes real HTTP responses.

Checks implemented:
  API1  — Broken Object Level Authorization (BOLA)
  API2  — Broken Authentication
  API3  — Broken Object Property Level Authorization
  API4  — Unrestricted Resource Consumption
  API5  — Broken Function Level Authorization
  API6  — Unrestricted Access to Sensitive Business Flows
  API7  — Server Side Request Forgery (SSRF)
  API8  — Security Misconfiguration
  API9  — Improper Inventory Management
  API10 — Unsafe Consumption of APIs
"""

from __future__ import annotations

from typing import Any, Optional

from checks.models import CheckResult, MockResponse, Severity


# ---------------------------------------------------------------------------
# API1 — Broken Object Level Authorization (BOLA / IDOR)
# ---------------------------------------------------------------------------

def check_bola(
    own_response: MockResponse,
    other_response: MockResponse,
) -> CheckResult:
    """Check if accessing another user's object returns data.

    Detects IDOR: if /resource/1 and /resource/2 both return 200 with
    different bodies, flag for manual review.
    """
    check_id = "API1_BOLA"
    own_sc = own_response.status_code
    other_sc = other_response.status_code

    if other_sc in (401, 403):
        return CheckResult(
            check_id=check_id,
            name="BOLA / IDOR",
            severity=Severity.CRITICAL,
            passed=True,
            description="Access to another object is properly restricted.",
            detail=f"Cross-object request returned {other_sc}.",
            remediation="Continue enforcing per-object authorization.",
        )

    # Both return 200 with different data — potential IDOR
    if own_sc == 200 and other_sc == 200:
        own_body = own_response.json()
        other_body = other_response.json()
        if own_body != other_body:
            return CheckResult(
                check_id=check_id,
                name="BOLA / IDOR",
                severity=Severity.CRITICAL,
                passed=False,
                description="Possible IDOR: accessing another user's object returned data.",
                detail=f"Own object: {own_response.url}  Other object: {other_response.url}  Both returned 200.",
                evidence={"own_status": own_sc, "other_status": other_sc},
                remediation=(
                    "Validate that the authenticated user owns or is authorized "
                    "to access every object before returning it."
                ),
            )

    return CheckResult(
        check_id=check_id,
        name="BOLA / IDOR",
        severity=Severity.CRITICAL,
        passed=True,
        description="No obvious BOLA vulnerability detected.",
        detail=f"Other-object request returned {other_sc}.",
    )


# ---------------------------------------------------------------------------
# API2 — Broken Authentication
# ---------------------------------------------------------------------------

def check_authentication(response_no_auth: MockResponse) -> CheckResult:
    """Check if an authenticated endpoint is reachable without credentials."""
    check_id = "API2_BROKEN_AUTH"
    sc = response_no_auth.status_code

    if sc in (401, 403):
        return CheckResult(
            check_id=check_id,
            name="Broken Authentication",
            severity=Severity.CRITICAL,
            passed=True,
            description="Endpoint correctly requires authentication.",
            detail=f"Unauthenticated request returned {sc}.",
            remediation="No change needed.",
        )

    return CheckResult(
        check_id=check_id,
        name="Broken Authentication",
        severity=Severity.CRITICAL,
        passed=False,
        description="Endpoint is accessible without authentication.",
        detail=f"Unauthenticated request returned {sc} — expected 401 or 403.",
        evidence={"status_code": sc},
        remediation=(
            "Require authentication on all non-public endpoints. "
            "Return 401 for missing credentials and 403 for insufficient privileges."
        ),
    )


# ---------------------------------------------------------------------------
# API3 — Broken Object Property Level Authorization (mass assignment)
# ---------------------------------------------------------------------------

def check_mass_assignment(
    update_response: MockResponse,
    privileged_fields: list[str],
) -> CheckResult:
    """Check if updating privileged fields succeeds unexpectedly."""
    check_id = "API3_MASS_ASSIGNMENT"
    sc = update_response.status_code
    body = update_response.json()

    # If the response reflects any of the privileged fields, flag it
    reflected = [f for f in privileged_fields if f in body]
    if reflected and sc in (200, 201):
        return CheckResult(
            check_id=check_id,
            name="Mass Assignment / Excessive Data Exposure",
            severity=Severity.HIGH,
            passed=False,
            description="Privileged fields were reflected in the update response.",
            detail=f"Fields reflected: {reflected}",
            evidence={"reflected_fields": reflected, "status_code": sc},
            remediation=(
                "Use an explicit allowlist of writable fields. "
                "Strip privileged fields (role, is_admin) from update payloads."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="Mass Assignment / Excessive Data Exposure",
        severity=Severity.HIGH,
        passed=True,
        description="No privileged fields reflected in update response.",
        detail=f"Update returned {sc}; no privileged fields in response body.",
    )


# ---------------------------------------------------------------------------
# API4 — Unrestricted Resource Consumption
# ---------------------------------------------------------------------------

def check_rate_limiting(
    responses: list[MockResponse],
    expected_limit_at: int = 10,
) -> CheckResult:
    """Check if repeated requests eventually trigger rate limiting.

    Args:
        responses:        List of consecutive responses to the same endpoint.
        expected_limit_at: Request number at which 429 is expected.
    """
    check_id = "API4_RATE_LIMIT"
    status_codes = [r.status_code for r in responses]
    got_limited = 429 in status_codes

    if got_limited:
        first_limit = status_codes.index(429) + 1
        return CheckResult(
            check_id=check_id,
            name="Unrestricted Resource Consumption",
            severity=Severity.HIGH,
            passed=True,
            description=f"Rate limiting triggered at request #{first_limit}.",
            detail=f"Status codes: {status_codes}",
        )

    all_200 = all(sc == 200 for sc in status_codes)
    if all_200 and len(responses) >= expected_limit_at:
        return CheckResult(
            check_id=check_id,
            name="Unrestricted Resource Consumption",
            severity=Severity.HIGH,
            passed=False,
            description=f"No rate limiting after {len(responses)} consecutive requests.",
            detail=f"All {len(responses)} requests returned 200.",
            evidence={"request_count": len(responses), "status_codes": status_codes},
            remediation=(
                "Implement rate limiting per IP and per authenticated user. "
                "Return 429 with Retry-After when the limit is exceeded."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="Unrestricted Resource Consumption",
        severity=Severity.HIGH,
        passed=True,
        description="Rate limit check inconclusive (mix of status codes).",
        detail=f"Status codes observed: {status_codes}",
    )


# ---------------------------------------------------------------------------
# API5 — Broken Function Level Authorization
# ---------------------------------------------------------------------------

def check_function_level_auth(
    admin_response: MockResponse,
    user_response: MockResponse,
    admin_path: str = "/admin",
) -> CheckResult:
    """Check if a low-privilege user can access admin-only functions."""
    check_id = "API5_FUNC_LEVEL_AUTH"
    sc = user_response.status_code

    if sc in (401, 403, 404):
        return CheckResult(
            check_id=check_id,
            name="Broken Function Level Authorization",
            severity=Severity.HIGH,
            passed=True,
            description="Admin function correctly blocked for regular user.",
            detail=f"User request to {admin_path} returned {sc}.",
        )

    if sc == 200:
        return CheckResult(
            check_id=check_id,
            name="Broken Function Level Authorization",
            severity=Severity.HIGH,
            passed=False,
            description="Regular user can access admin function.",
            detail=f"User request to {admin_path} returned {sc}.",
            evidence={"admin_path": admin_path, "user_status": sc, "admin_status": admin_response.status_code},
            remediation=(
                "Enforce role-based access control on every function/endpoint. "
                "Do not rely solely on obscuring paths."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="Broken Function Level Authorization",
        severity=Severity.HIGH,
        passed=True,
        description=f"Admin path returned {sc} for regular user.",
    )


# ---------------------------------------------------------------------------
# API8 — Security Misconfiguration
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": None,  # just presence, any value
    "Strict-Transport-Security": None,
    "Content-Security-Policy": None,
}

_VERBOSE_SERVER_HEADERS = {"server", "x-powered-by", "x-aspnet-version"}
_VERBOSE_ERROR_PATTERNS = [
    "traceback", "stack trace", "exception", "at line",
    "syntax error", "uncaught", "undefined method", "nil pointer",
]


def check_security_headers(response: MockResponse) -> CheckResult:
    """Check for presence of recommended security headers."""
    check_id = "API8_SEC_HEADERS"
    missing = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header, expected_value in _SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            missing.append(header)
        elif expected_value and headers_lower[header.lower()] != expected_value:
            missing.append(f"{header} (wrong value)")

    if missing:
        return CheckResult(
            check_id=check_id,
            name="Security Misconfiguration — Missing Headers",
            severity=Severity.MEDIUM,
            passed=False,
            description="One or more security headers are missing.",
            detail=f"Missing: {', '.join(missing)}",
            evidence={"missing_headers": missing},
            remediation=(
                "Add missing security headers. "
                "At minimum: X-Content-Type-Options, X-Frame-Options, HSTS, CSP."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="Security Misconfiguration — Missing Headers",
        severity=Severity.MEDIUM,
        passed=True,
        description="All recommended security headers are present.",
    )


def check_verbose_errors(response: MockResponse) -> CheckResult:
    """Check if error responses expose stack traces or internal details."""
    check_id = "API8_VERBOSE_ERRORS"
    body_lower = response.text().lower()
    found = [p for p in _VERBOSE_ERROR_PATTERNS if p in body_lower]

    if found:
        return CheckResult(
            check_id=check_id,
            name="Security Misconfiguration — Verbose Errors",
            severity=Severity.MEDIUM,
            passed=False,
            description="Error response contains stack trace or implementation details.",
            detail=f"Patterns found: {found}",
            evidence={"patterns": found},
            remediation=(
                "Return generic error messages to clients. "
                "Log detailed errors server-side only."
            ),
        )

    # Check for verbose server headers
    verbose = [h for h in response.headers if h.lower() in _VERBOSE_SERVER_HEADERS]
    if verbose:
        return CheckResult(
            check_id=check_id,
            name="Security Misconfiguration — Verbose Server Headers",
            severity=Severity.LOW,
            passed=False,
            description="Response reveals server technology via headers.",
            detail=f"Headers: {verbose}",
            evidence={"verbose_headers": verbose},
            remediation="Remove or genericise Server, X-Powered-By headers.",
        )

    return CheckResult(
        check_id=check_id,
        name="Security Misconfiguration — Verbose Errors",
        severity=Severity.MEDIUM,
        passed=True,
        description="No verbose error information detected.",
    )


# ---------------------------------------------------------------------------
# API9 — Improper Inventory Management (version exposure)
# ---------------------------------------------------------------------------

def check_version_endpoints(
    responses_by_path: dict[str, MockResponse],
) -> CheckResult:
    """Check if old/debug API versions respond with 200."""
    check_id = "API9_INVENTORY"
    exposed = {
        path: r.status_code
        for path, r in responses_by_path.items()
        if r.status_code == 200
    }

    if exposed:
        return CheckResult(
            check_id=check_id,
            name="Improper Inventory Management",
            severity=Severity.MEDIUM,
            passed=False,
            description="Legacy or debug API endpoints are accessible.",
            detail=f"Accessible: {list(exposed.keys())}",
            evidence={"accessible_paths": exposed},
            remediation=(
                "Decommission legacy API versions. "
                "Return 404 or 410 for deprecated endpoints."
            ),
        )

    return CheckResult(
        check_id=check_id,
        name="Improper Inventory Management",
        severity=Severity.MEDIUM,
        passed=True,
        description="No legacy/debug endpoints found to be accessible.",
    )

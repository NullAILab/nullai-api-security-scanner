"""Parameter fuzzer — generates payloads and categorises responses.

The fuzzer systematically probes API endpoints with injection payloads to
detect anomalous responses that indicate vulnerabilities.  It does NOT
execute exploits; it identifies *candidate* vulnerabilities for manual review.

Categories:
  - SQL injection probes
  - Path traversal probes
  - XSS / template injection probes
  - SSRF probes
  - Integer boundary probes
  - Format string probes
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from checks.models import CheckResult, Severity


@dataclass
class FuzzPayload:
    category: str
    value: Any
    description: str


@dataclass
class FuzzResponse:
    payload: FuzzPayload
    status_code: int
    body: Any
    response_time_ms: float = 0.0


@dataclass
class FuzzFinding:
    category: str
    payload: str
    status_code: int
    reason: str
    severity: str


# ---------------------------------------------------------------------------
# Payload library
# ---------------------------------------------------------------------------

SQL_PAYLOADS: list[FuzzPayload] = [
    FuzzPayload("sql_injection", "' OR '1'='1", "Classic OR injection"),
    FuzzPayload("sql_injection", "'; DROP TABLE users; --", "DROP statement"),
    FuzzPayload("sql_injection", "1 UNION SELECT null, version(), null --", "UNION version"),
    FuzzPayload("sql_injection", "1' AND SLEEP(5) --", "Time-based blind (MySQL)"),
    FuzzPayload("sql_injection", "1' AND 1=CONVERT(int, @@version) --", "Error-based (MSSQL)"),
]

PATH_TRAVERSAL_PAYLOADS: list[FuzzPayload] = [
    FuzzPayload("path_traversal", "../etc/passwd", "Unix path traversal"),
    FuzzPayload("path_traversal", "..\\..\\Windows\\win.ini", "Windows path traversal"),
    FuzzPayload("path_traversal", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
    FuzzPayload("path_traversal", "....//....//etc/passwd", "Double-slash bypass"),
]

XSS_PAYLOADS: list[FuzzPayload] = [
    FuzzPayload("xss", "<script>alert(1)</script>", "Basic XSS"),
    FuzzPayload("xss", "{{7*7}}", "Template injection probe (SSTI)"),
    FuzzPayload("xss", "${7*7}", "EL / server-side template injection"),
    FuzzPayload("xss", "{% import os %}{{os.listdir('.')}}", "Jinja2 SSTI"),
]

SSRF_PAYLOADS: list[FuzzPayload] = [
    FuzzPayload("ssrf", "http://169.254.169.254/latest/meta-data/", "AWS metadata SSRF"),
    FuzzPayload("ssrf", "http://127.0.0.1:22", "Localhost port probe"),
    FuzzPayload("ssrf", "http://[::1]/", "IPv6 localhost SSRF"),
    FuzzPayload("ssrf", "file:///etc/passwd", "File scheme SSRF"),
]

INTEGER_PAYLOADS: list[FuzzPayload] = [
    FuzzPayload("integer_boundary", -1, "Negative ID"),
    FuzzPayload("integer_boundary", 0, "Zero ID"),
    FuzzPayload("integer_boundary", 2**31 - 1, "INT_MAX"),
    FuzzPayload("integer_boundary", 2**63, "INT64 overflow"),
    FuzzPayload("integer_boundary", "null", "Null as integer"),
    FuzzPayload("integer_boundary", "undefined", "Undefined as integer"),
]

ALL_PAYLOADS: list[FuzzPayload] = (
    SQL_PAYLOADS
    + PATH_TRAVERSAL_PAYLOADS
    + XSS_PAYLOADS
    + SSRF_PAYLOADS
    + INTEGER_PAYLOADS
)


# ---------------------------------------------------------------------------
# Response analyser
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
    "unclosed quotation", "invalid input syntax", "sqlexception",
    "odbc driver", "syntax error near",
]

_PATH_TRAVERSAL_INDICATORS = [
    "root:x:", "daemon:x:", "[extensions]", "windows registry",
    "etc/passwd", "boot.ini",
]

_SSTI_INDICATORS = ["49", "7*7=49", "<49>"]  # result of {{7*7}}


def analyse_fuzz_response(fr: FuzzResponse) -> list[FuzzFinding]:
    """Analyse a fuzz response for security anomalies."""
    findings: list[FuzzFinding] = []
    body_lower = str(fr.body).lower() if fr.body else ""
    sc = fr.status_code

    cat = fr.payload.category

    if cat == "sql_injection":
        sql_errors = [p for p in _SQL_ERROR_PATTERNS if p in body_lower]
        if sql_errors:
            findings.append(FuzzFinding(
                category="sql_injection",
                payload=str(fr.payload.value),
                status_code=sc,
                reason=f"SQL error pattern in response: {sql_errors}",
                severity=Severity.CRITICAL,
            ))
        # Time-based: a 5-second sleep payload returned quickly might indicate WAF bypass
        if fr.response_time_ms > 4000 and "sleep" in str(fr.payload.value).lower():
            findings.append(FuzzFinding(
                category="sql_injection_time_based",
                payload=str(fr.payload.value),
                status_code=sc,
                reason=f"Response took {fr.response_time_ms:.0f}ms — possible time-based SQLi",
                severity=Severity.HIGH,
            ))

    elif cat == "path_traversal":
        pt_indicators = [p for p in _PATH_TRAVERSAL_INDICATORS if p in body_lower]
        if pt_indicators and sc == 200:
            findings.append(FuzzFinding(
                category="path_traversal",
                payload=str(fr.payload.value),
                status_code=sc,
                reason=f"Path traversal indicator in response: {pt_indicators}",
                severity=Severity.CRITICAL,
            ))

    elif cat == "xss":
        value_str = str(fr.payload.value)
        if value_str in str(fr.body):
            # Payload reflected verbatim
            findings.append(FuzzFinding(
                category="xss_reflection",
                payload=value_str,
                status_code=sc,
                reason="Payload reflected verbatim in response",
                severity=Severity.HIGH,
            ))
        ssti = [i for i in _SSTI_INDICATORS if i in body_lower]
        if ssti:
            findings.append(FuzzFinding(
                category="ssti",
                payload=value_str,
                status_code=sc,
                reason=f"SSTI indicators in response: {ssti}",
                severity=Severity.CRITICAL,
            ))

    elif cat == "ssrf":
        # 200 response to an SSRF probe is a strong indicator
        if sc == 200 and fr.body:
            findings.append(FuzzFinding(
                category="ssrf",
                payload=str(fr.payload.value),
                status_code=sc,
                reason="SSRF probe returned 200 with body data",
                severity=Severity.CRITICAL,
            ))

    elif cat == "integer_boundary":
        # 500 errors on integer probes suggest poor input validation
        if sc == 500:
            findings.append(FuzzFinding(
                category="integer_error",
                payload=str(fr.payload.value),
                status_code=sc,
                reason="Integer boundary probe caused 500 — unhandled exception",
                severity=Severity.MEDIUM,
            ))

    return findings


def summarise_fuzz_results(
    fuzz_responses: list[FuzzResponse],
) -> CheckResult:
    """Turn a list of fuzz responses into a single CheckResult."""
    all_findings: list[FuzzFinding] = []
    for fr in fuzz_responses:
        all_findings.extend(analyse_fuzz_response(fr))

    if not all_findings:
        return CheckResult(
            check_id="FUZZ_SUMMARY",
            name="Parameter Fuzzing",
            severity=Severity.INFO,
            passed=True,
            description=f"Fuzzed {len(fuzz_responses)} payloads — no anomalous responses.",
        )

    sev_order = {
        Severity.CRITICAL: 5, Severity.HIGH: 4,
        Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1,
    }
    worst_sev = max(all_findings, key=lambda f: sev_order.get(f.severity, 0)).severity

    return CheckResult(
        check_id="FUZZ_SUMMARY",
        name="Parameter Fuzzing",
        severity=worst_sev,
        passed=False,
        description=f"Fuzzing found {len(all_findings)} anomal{'y' if len(all_findings) == 1 else 'ies'}.",
        detail="\n".join(f"[{f.severity}] {f.category}: {f.reason}" for f in all_findings),
        evidence={"findings": [
            {"category": f.category, "payload": f.payload, "reason": f.reason, "severity": f.severity}
            for f in all_findings
        ]},
        remediation=(
            "Validate and sanitise all input parameters. "
            "Use parameterised queries. Never reflect user input without encoding."
        ),
    )

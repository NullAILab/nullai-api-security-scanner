"""FastAPI routes for the API Security Scanner web interface.

Endpoints:
  POST /api/scan          — full scan against a target URL
  POST /api/check/auth    — standalone authentication check
  POST /api/check/headers — standalone security-headers check
  POST /api/check/fuzz    — standalone fuzzing run
  GET  /api/health        — liveness probe
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from checks.models import MockResponse, ScanReport, Severity
from checks.owasp_api import (
    check_authentication,
    check_security_headers,
    check_verbose_errors,
    check_rate_limiting,
    check_version_endpoints,
)
from checks.graphql import check_introspection, check_depth_limit
from checks.fuzzer import ALL_PAYLOADS, FuzzResponse, summarise_fuzz_results
from scanner.engine import APIScanner

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    auth_headers: Optional[dict] = None
    check_auth: bool = True
    check_headers: bool = True
    check_versions: bool = True
    check_graphql: bool = False
    check_fuzz: bool = False
    graphql_path: str = "/graphql"
    fuzz_path: str = "/api/items"
    fuzz_param: str = "id"
    timeout: int = 5


class MockScanRequest(BaseModel):
    """Scan using pre-supplied mock responses — for demo / testing."""
    target: str = "http://example.com"
    status_code: int = 200
    headers: Optional[dict] = None
    body: Optional[dict] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/api/health")
def health():
    return {"status": "ok"}


@router.post("/api/scan")
def run_scan(req: ScanRequest):
    """Run a real scan against the target URL."""
    scanner = APIScanner(
        base_url=req.target,
        auth_headers=req.auth_headers,
        timeout=req.timeout,
    )
    report: ScanReport = scanner.run(
        check_auth=req.check_auth,
        check_headers=req.check_headers,
        check_versions=req.check_versions,
        check_graphql=req.check_graphql,
        check_fuzz=req.check_fuzz,
        graphql_path=req.graphql_path,
        fuzz_path=req.fuzz_path,
        fuzz_param=req.fuzz_param,
    )
    return report.to_dict()


@router.post("/api/demo/auth")
def demo_auth_check(req: MockScanRequest):
    """Demonstrate the authentication check with a mock response."""
    resp = MockResponse(
        status_code=req.status_code,
        headers=req.headers or {},
        body=req.body,
        url=f"{req.target}/api/me",
    )
    result = check_authentication(resp)
    return {
        "check_id": result.check_id,
        "name": result.name,
        "severity": result.severity,
        "status": result.status,
        "description": result.description,
        "detail": result.detail,
        "remediation": result.remediation,
    }


@router.post("/api/demo/headers")
def demo_headers_check(req: MockScanRequest):
    """Demonstrate the security-headers check with a mock response."""
    resp = MockResponse(
        status_code=req.status_code,
        headers=req.headers or {},
        body=req.body,
        url=req.target,
    )
    sec = check_security_headers(resp)
    verbose = check_verbose_errors(resp)
    return {
        "security_headers": {
            "check_id": sec.check_id,
            "status": sec.status,
            "description": sec.description,
            "detail": sec.detail,
        },
        "verbose_errors": {
            "check_id": verbose.check_id,
            "status": verbose.status,
            "description": verbose.description,
            "detail": verbose.detail,
        },
    }


@router.post("/api/demo/fuzz")
def demo_fuzz(req: MockScanRequest):
    """Run all fuzzing payloads against a mock response — shows what would be detected."""
    fuzz_results: list[FuzzResponse] = []
    for payload in ALL_PAYLOADS:
        fuzz_results.append(FuzzResponse(
            payload=payload,
            status_code=req.status_code,
            body=req.body or {},
            response_time_ms=0.0,
        ))
    result = summarise_fuzz_results(fuzz_results)
    return {
        "check_id": result.check_id,
        "status": result.status,
        "severity": result.severity,
        "description": result.description,
        "detail": result.detail,
        "evidence": result.evidence,
        "remediation": result.remediation,
    }


@router.get("/api/payloads")
def list_payloads():
    """Return the full payload library grouped by category."""
    categories: dict[str, list] = {}
    for p in ALL_PAYLOADS:
        categories.setdefault(p.category, []).append({
            "value": str(p.value),
            "description": p.description,
        })
    return {"total": len(ALL_PAYLOADS), "categories": categories}

"""Scanner engine — orchestrates checks against a target API.

The engine makes real HTTP requests (via urllib) to a target base URL
and runs all enabled checks.  For testing, pass a custom http_client
that returns MockResponse objects without making real network calls.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from checks.models import CheckResult, MockResponse, ScanReport, Severity
from checks.owasp_api import (
    check_authentication,
    check_security_headers,
    check_verbose_errors,
    check_rate_limiting,
    check_version_endpoints,
)
from checks.graphql import (
    check_introspection,
    check_depth_limit,
)
from checks.fuzzer import (
    ALL_PAYLOADS,
    FuzzResponse,
    summarise_fuzz_results,
)


# ---------------------------------------------------------------------------
# HTTP client adapter
# ---------------------------------------------------------------------------

HttpClient = Callable[[str, str, Optional[dict], Optional[bytes]], MockResponse]


def _default_http_client(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body: Optional[bytes] = None,
    timeout: int = 5,
) -> MockResponse:
    """Make a real HTTP request and return a MockResponse-compatible object."""
    req = urllib.request.Request(
        url,
        data=body,
        headers=headers or {"User-Agent": "NullAILab-API-Scanner/1.0"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_body = resp.read()
            resp_headers = dict(resp.headers)
            try:
                parsed_body = json.loads(raw_body)
            except json.JSONDecodeError:
                parsed_body = raw_body.decode(errors="replace")
            return MockResponse(
                status_code=resp.status,
                headers=resp_headers,
                body=parsed_body,
                url=url,
            )
    except urllib.error.HTTPError as e:
        return MockResponse(status_code=e.code, headers=dict(e.headers), url=url)
    except Exception:
        return MockResponse(status_code=0, url=url)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class APIScanner:
    """Orchestrates all enabled checks against a target API."""

    def __init__(
        self,
        base_url: str,
        http_client: Optional[HttpClient] = None,
        auth_headers: Optional[dict] = None,
        timeout: int = 5,
    ):
        self.base_url = base_url.rstrip("/")
        self._http = http_client or _default_http_client
        self.auth_headers = auth_headers or {}
        self.timeout = timeout

    def _get(self, path: str, headers: Optional[dict] = None) -> MockResponse:
        url = f"{self.base_url}{path}"
        h = {**self.auth_headers, **(headers or {})}
        return self._http(url, "GET", h or None, None)

    def _post(
        self,
        path: str,
        payload: dict,
        headers: Optional[dict] = None,
    ) -> MockResponse:
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode()
        h = {
            "Content-Type": "application/json",
            **self.auth_headers,
            **(headers or {}),
        }
        return self._http(url, "POST", h, body)

    def run(
        self,
        *,
        check_auth: bool = True,
        check_headers: bool = True,
        check_versions: bool = True,
        check_graphql: bool = False,
        check_fuzz: bool = False,
        graphql_path: str = "/graphql",
        fuzz_path: str = "/api/items",
        fuzz_param: str = "id",
    ) -> ScanReport:
        """Run enabled checks and return a ScanReport."""
        report = ScanReport(target=self.base_url)

        # API2 — Authentication check
        if check_auth:
            no_auth = MockResponse.__new__(MockResponse)
            no_auth.__init__(
                status_code=self._http(
                    f"{self.base_url}/api/me", "GET", {}, None
                ).status_code,
                url=f"{self.base_url}/api/me",
            )
            report.checks.append(check_authentication(no_auth))

        # API8 — Security headers + verbose errors
        if check_headers:
            resp = self._get("/")
            report.checks.append(check_security_headers(resp))
            report.checks.append(check_verbose_errors(resp))

        # API9 — Legacy versions
        if check_versions:
            version_paths = ["/v0", "/v1", "/v2", "/api/v0", "/api/debug", "/swagger", "/openapi.json"]
            version_responses = {p: self._get(p) for p in version_paths}
            report.checks.append(check_version_endpoints(version_responses))

        # GraphQL checks
        if check_graphql:
            gql_resp = self._post(
                graphql_path,
                {"query": "{ __schema { queryType { name } } }"},
            )
            report.checks.append(check_introspection(gql_resp))

            # Depth limit: test depths 5, 10, 20
            depth_responses = {}
            for depth in [5, 10, 20]:
                depth_responses[depth] = self._post(
                    graphql_path,
                    {"query": "{ " + "user { " * depth + "id " + "} " * depth + "}"},
                )
            report.checks.append(check_depth_limit(depth_responses))

        # Fuzzing
        if check_fuzz:
            fuzz_results: list[FuzzResponse] = []
            for payload in ALL_PAYLOADS[:20]:  # limit to 20 in scanner
                t0 = time.time()
                resp = self._get(f"{fuzz_path}?{fuzz_param}={payload.value}")
                elapsed = (time.time() - t0) * 1000
                fuzz_results.append(FuzzResponse(
                    payload=payload,
                    status_code=resp.status_code,
                    body=resp.body,
                    response_time_ms=elapsed,
                ))
            report.checks.append(summarise_fuzz_results(fuzz_results))

        return report

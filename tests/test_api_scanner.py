"""Tests for the API Security Scanner — all offline, no real HTTP calls."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from checks.models import CheckResult, MockResponse, ScanReport, Severity
from checks.owasp_api import (
    check_authentication,
    check_bola,
    check_function_level_auth,
    check_mass_assignment,
    check_rate_limiting,
    check_security_headers,
    check_verbose_errors,
    check_version_endpoints,
)
from checks.graphql import (
    check_alias_abuse,
    check_batch_queries,
    check_depth_limit,
    check_introspection,
)
from checks.fuzzer import (
    ALL_PAYLOADS,
    FuzzPayload,
    FuzzResponse,
    analyse_fuzz_response,
    summarise_fuzz_results,
)
from scanner.engine import APIScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_resp(status=200, headers=None, body=None, url="http://example.com/api"):
    return MockResponse(status_code=status, headers=headers or {}, body=body, url=url)


def mock_client(responses: dict):
    """Return an http_client that maps URL → MockResponse."""
    def client(url, method="GET", headers=None, body=None):
        for key, resp in responses.items():
            if key in url:
                return resp
        return MockResponse(status_code=404, url=url)
    return client


# ---------------------------------------------------------------------------
# MockResponse
# ---------------------------------------------------------------------------

class TestMockResponse:
    def test_json_dict(self):
        r = make_resp(body={"key": "val"})
        assert r.json() == {"key": "val"}

    def test_json_list(self):
        r = make_resp(body=[1, 2, 3])
        assert r.json() == [1, 2, 3]

    def test_json_non_json_returns_empty(self):
        r = make_resp(body="plain text")
        assert r.json() == {}

    def test_text(self):
        r = make_resp(body="hello world")
        assert r.text() == "hello world"

    def test_text_empty(self):
        r = make_resp(body=None)
        assert r.text() == ""


# ---------------------------------------------------------------------------
# OWASP API checks
# ---------------------------------------------------------------------------

class TestCheckAuthentication:
    def test_401_passes(self):
        result = check_authentication(make_resp(status=401))
        assert result.passed
        assert result.severity == Severity.CRITICAL

    def test_403_passes(self):
        result = check_authentication(make_resp(status=403))
        assert result.passed

    def test_200_fails(self):
        result = check_authentication(make_resp(status=200))
        assert not result.passed
        assert result.severity == Severity.CRITICAL

    def test_500_fails(self):
        result = check_authentication(make_resp(status=500))
        assert not result.passed

    def test_check_id(self):
        result = check_authentication(make_resp(status=401))
        assert result.check_id == "API2_BROKEN_AUTH"


class TestCheckBola:
    def test_other_403_passes(self):
        own = make_resp(status=200, body={"id": 1})
        other = make_resp(status=403)
        result = check_bola(own, other)
        assert result.passed

    def test_other_401_passes(self):
        own = make_resp(status=200, body={"id": 1})
        other = make_resp(status=401)
        result = check_bola(own, other)
        assert result.passed

    def test_both_200_different_bodies_fails(self):
        own = make_resp(status=200, body={"id": 1, "name": "Alice"})
        other = make_resp(status=200, body={"id": 2, "name": "Bob"})
        result = check_bola(own, other)
        assert not result.passed
        assert result.severity == Severity.CRITICAL

    def test_both_200_same_body_passes(self):
        own = make_resp(status=200, body={"id": 1})
        other = make_resp(status=200, body={"id": 1})
        result = check_bola(own, other)
        assert result.passed


class TestCheckMassAssignment:
    def test_privileged_field_reflected_fails(self):
        resp = make_resp(status=200, body={"is_admin": True, "name": "Alice"})
        result = check_mass_assignment(resp, ["is_admin", "role"])
        assert not result.passed
        assert result.severity == Severity.HIGH

    def test_no_privileged_fields_passes(self):
        resp = make_resp(status=200, body={"name": "Alice"})
        result = check_mass_assignment(resp, ["is_admin", "role"])
        assert result.passed

    def test_non_200_passes(self):
        resp = make_resp(status=403, body={"is_admin": True})
        result = check_mass_assignment(resp, ["is_admin"])
        assert result.passed


class TestCheckRateLimiting:
    def test_429_present_passes(self):
        resps = [make_resp(200)] * 5 + [make_resp(429)]
        result = check_rate_limiting(resps)
        assert result.passed
        assert "request #6" in result.description

    def test_no_429_after_threshold_fails(self):
        resps = [make_resp(200)] * 15
        result = check_rate_limiting(resps, expected_limit_at=10)
        assert not result.passed
        assert result.severity == Severity.HIGH

    def test_mixed_codes_inconclusive(self):
        resps = [make_resp(200), make_resp(500), make_resp(200)]
        result = check_rate_limiting(resps, expected_limit_at=10)
        assert result.passed  # inconclusive → pass


class TestCheckFunctionLevelAuth:
    def test_403_for_user_passes(self):
        admin = make_resp(200)
        user = make_resp(403)
        result = check_function_level_auth(admin, user, "/admin")
        assert result.passed

    def test_404_for_user_passes(self):
        admin = make_resp(200)
        user = make_resp(404)
        result = check_function_level_auth(admin, user, "/admin")
        assert result.passed

    def test_200_for_user_fails(self):
        admin = make_resp(200)
        user = make_resp(200)
        result = check_function_level_auth(admin, user, "/admin")
        assert not result.passed
        assert result.severity == Severity.HIGH


class TestCheckSecurityHeaders:
    def test_all_headers_present_passes(self):
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }
        result = check_security_headers(make_resp(headers=headers))
        assert result.passed

    def test_missing_header_fails(self):
        headers = {"X-Content-Type-Options": "nosniff"}
        result = check_security_headers(make_resp(headers=headers))
        assert not result.passed
        assert result.severity == Severity.MEDIUM

    def test_wrong_xcto_value_fails(self):
        headers = {
            "X-Content-Type-Options": "something-wrong",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        }
        result = check_security_headers(make_resp(headers=headers))
        assert not result.passed

    def test_case_insensitive_headers(self):
        headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
        }
        result = check_security_headers(make_resp(headers=headers))
        assert result.passed


class TestCheckVerboseErrors:
    def test_stack_trace_fails(self):
        resp = make_resp(body="Traceback (most recent call last): File app.py line 42")
        result = check_verbose_errors(resp)
        assert not result.passed

    def test_sql_syntax_error_fails(self):
        resp = make_resp(body="syntax error near 'SELECT'")
        result = check_verbose_errors(resp)
        assert not result.passed

    def test_verbose_server_header_fails(self):
        resp = make_resp(headers={"X-Powered-By": "PHP/7.4"})
        result = check_verbose_errors(resp)
        assert not result.passed
        assert result.severity == Severity.LOW

    def test_clean_response_passes(self):
        resp = make_resp(body={"message": "ok"})
        result = check_verbose_errors(resp)
        assert result.passed


class TestCheckVersionEndpoints:
    def test_accessible_path_fails(self):
        responses = {
            "/v0": make_resp(200),
            "/v1": make_resp(404),
            "/swagger": make_resp(404),
        }
        result = check_version_endpoints(responses)
        assert not result.passed
        assert "/v0" in result.detail

    def test_all_404_passes(self):
        responses = {
            "/v0": make_resp(404),
            "/v1": make_resp(404),
            "/swagger": make_resp(404),
        }
        result = check_version_endpoints(responses)
        assert result.passed

    def test_multiple_accessible_listed(self):
        responses = {"/v0": make_resp(200), "/swagger": make_resp(200)}
        result = check_version_endpoints(responses)
        assert not result.passed
        assert result.evidence is not None
        assert len(result.evidence["accessible_paths"]) == 2


# ---------------------------------------------------------------------------
# GraphQL checks
# ---------------------------------------------------------------------------

class TestGraphQLIntrospection:
    def test_introspection_enabled_fails(self):
        body = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        resp = make_resp(status=200, body=body)
        result = check_introspection(resp)
        assert not result.passed
        assert result.severity == Severity.MEDIUM

    def test_introspection_disabled_passes(self):
        body = {"errors": [{"message": "introspection disabled"}]}
        resp = make_resp(status=200, body=body)
        result = check_introspection(resp)
        assert result.passed

    def test_non_200_passes(self):
        resp = make_resp(status=400)
        result = check_introspection(resp)
        assert result.passed


class TestGraphQLDepthLimit:
    def test_no_limit_fails(self):
        responses = {5: make_resp(200), 10: make_resp(200), 20: make_resp(200)}
        result = check_depth_limit(responses)
        assert not result.passed
        assert result.severity == Severity.HIGH

    def test_depth_rejected_passes(self):
        responses = {5: make_resp(200), 10: make_resp(400), 20: make_resp(400)}
        result = check_depth_limit(responses)
        assert result.passed
        assert "depth 10" in result.description

    def test_all_rejected_passes(self):
        responses = {5: make_resp(400), 10: make_resp(400)}
        result = check_depth_limit(responses)
        assert result.passed


class TestGraphQLAliasAbuse:
    def test_many_aliases_fails(self):
        data = {f"a{i}": {"id": i} for i in range(100)}
        resp = make_resp(status=200, body={"data": data})
        result = check_alias_abuse(resp, alias_count=100)
        assert not result.passed

    def test_few_aliases_passes(self):
        resp = make_resp(status=200, body={"data": {"a1": {"id": 1}}})
        result = check_alias_abuse(resp, alias_count=100)
        assert result.passed

    def test_non_200_passes(self):
        resp = make_resp(status=400)
        result = check_alias_abuse(resp, alias_count=100)
        assert result.passed


class TestGraphQLBatchQueries:
    def test_large_batch_fails(self):
        results = [{"data": {"id": i}} for i in range(50)]
        resp = make_resp(status=200, body=results)
        result = check_batch_queries(resp, batch_size=50)
        assert not result.passed

    def test_small_batch_passes(self):
        results = [{"data": {"id": 1}}]
        resp = make_resp(status=200, body=results)
        result = check_batch_queries(resp, batch_size=50)
        assert result.passed

    def test_non_list_body_passes(self):
        resp = make_resp(status=200, body={"data": {}})
        result = check_batch_queries(resp, batch_size=50)
        assert result.passed


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class TestFuzzerPayloads:
    def test_all_payloads_have_required_fields(self):
        for p in ALL_PAYLOADS:
            assert p.category
            assert p.description
            assert p.value is not None

    def test_categories_present(self):
        cats = {p.category for p in ALL_PAYLOADS}
        assert "sql_injection" in cats
        assert "path_traversal" in cats
        assert "xss" in cats
        assert "ssrf" in cats
        assert "integer_boundary" in cats

    def test_payload_count(self):
        assert len(ALL_PAYLOADS) >= 19


class TestAnalyseFuzzResponse:
    def test_sql_error_detected(self):
        payload = FuzzPayload("sql_injection", "' OR '1'='1", "test")
        fr = FuzzResponse(payload=payload, status_code=200, body="sql syntax error in query")
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "sql_injection" for f in findings)
        assert findings[0].severity == Severity.CRITICAL

    def test_sql_time_based_detected(self):
        payload = FuzzPayload("sql_injection", "1' AND SLEEP(5) --", "time-based")
        fr = FuzzResponse(payload=payload, status_code=200, body="ok", response_time_ms=5000)
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "sql_injection_time_based" for f in findings)

    def test_sql_no_error_no_finding(self):
        payload = FuzzPayload("sql_injection", "' OR '1'='1", "test")
        fr = FuzzResponse(payload=payload, status_code=200, body={"data": []})
        findings = analyse_fuzz_response(fr)
        assert findings == []

    def test_path_traversal_detected(self):
        payload = FuzzPayload("path_traversal", "../etc/passwd", "test")
        fr = FuzzResponse(payload=payload, status_code=200, body="root:x:0:0:root:/root:/bin/bash")
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "path_traversal" for f in findings)
        assert findings[0].severity == Severity.CRITICAL

    def test_path_traversal_non_200_no_finding(self):
        payload = FuzzPayload("path_traversal", "../etc/passwd", "test")
        fr = FuzzResponse(payload=payload, status_code=403, body="root:x:0:0")
        findings = analyse_fuzz_response(fr)
        assert findings == []

    def test_xss_reflection_detected(self):
        xss_val = "<script>alert(1)</script>"
        payload = FuzzPayload("xss", xss_val, "XSS test")
        fr = FuzzResponse(payload=payload, status_code=200, body=f"input was: {xss_val}")
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "xss_reflection" for f in findings)

    def test_ssti_detected(self):
        payload = FuzzPayload("xss", "{{7*7}}", "SSTI probe")
        fr = FuzzResponse(payload=payload, status_code=200, body="result is 49")
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "ssti" for f in findings)

    def test_ssrf_detected(self):
        payload = FuzzPayload("ssrf", "http://169.254.169.254/latest/meta-data/", "AWS SSRF")
        fr = FuzzResponse(payload=payload, status_code=200, body={"ami-id": "ami-12345"})
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "ssrf" for f in findings)
        assert findings[0].severity == Severity.CRITICAL

    def test_ssrf_non_200_no_finding(self):
        payload = FuzzPayload("ssrf", "http://169.254.169.254/", "SSRF")
        fr = FuzzResponse(payload=payload, status_code=403, body=None)
        findings = analyse_fuzz_response(fr)
        assert findings == []

    def test_integer_500_detected(self):
        payload = FuzzPayload("integer_boundary", 2**63, "overflow")
        fr = FuzzResponse(payload=payload, status_code=500, body="Internal Server Error")
        findings = analyse_fuzz_response(fr)
        assert any(f.category == "integer_error" for f in findings)
        assert findings[0].severity == Severity.MEDIUM

    def test_integer_200_no_finding(self):
        payload = FuzzPayload("integer_boundary", -1, "negative")
        fr = FuzzResponse(payload=payload, status_code=200, body={"items": []})
        findings = analyse_fuzz_response(fr)
        assert findings == []


class TestSummariseFuzzResults:
    def test_no_findings_passes(self):
        fuzz = [
            FuzzResponse(FuzzPayload("integer_boundary", 0, "zero"), 200, {})
        ]
        result = summarise_fuzz_results(fuzz)
        assert result.passed
        assert result.severity == Severity.INFO

    def test_findings_fail(self):
        payload = FuzzPayload("sql_injection", "' OR '1'='1", "test")
        fuzz = [FuzzResponse(payload, 200, "sql syntax error")]
        result = summarise_fuzz_results(fuzz)
        assert not result.passed
        assert result.severity == Severity.CRITICAL

    def test_worst_severity_wins(self):
        p_med = FuzzPayload("integer_boundary", 2**63, "overflow")
        p_crit = FuzzPayload("sql_injection", "' OR '1'='1", "test")
        fuzz = [
            FuzzResponse(p_med, 500, "error"),
            FuzzResponse(p_crit, 200, "sql syntax error"),
        ]
        result = summarise_fuzz_results(fuzz)
        assert result.severity == Severity.CRITICAL

    def test_evidence_included(self):
        payload = FuzzPayload("sql_injection", "x", "test")
        fuzz = [FuzzResponse(payload, 200, "sql syntax error")]
        result = summarise_fuzz_results(fuzz)
        assert result.evidence is not None
        assert "findings" in result.evidence
        assert len(result.evidence["findings"]) >= 1

    def test_remediation_included_on_failure(self):
        payload = FuzzPayload("sql_injection", "x", "test")
        fuzz = [FuzzResponse(payload, 200, "sql syntax error")]
        result = summarise_fuzz_results(fuzz)
        assert result.remediation


# ---------------------------------------------------------------------------
# ScanReport
# ---------------------------------------------------------------------------

class TestScanReport:
    def test_failed_property(self):
        report = ScanReport(target="http://example.com")
        report.checks.append(CheckResult("A", "A", Severity.HIGH, False, "fail"))
        report.checks.append(CheckResult("B", "B", Severity.LOW, True, "pass"))
        assert len(report.failed) == 1
        assert len(report.passed) == 1

    def test_risk_score_critical(self):
        report = ScanReport(target="http://example.com")
        report.checks.append(CheckResult("A", "A", Severity.CRITICAL, False, "desc"))
        report.checks.append(CheckResult("B", "B", Severity.LOW, False, "desc"))
        assert report.risk_score == Severity.CRITICAL

    def test_risk_score_no_failures_is_info(self):
        report = ScanReport(target="http://example.com")
        report.checks.append(CheckResult("A", "A", Severity.HIGH, True, "pass"))
        assert report.risk_score == "INFO"

    def test_to_dict_structure(self):
        report = ScanReport(target="http://example.com")
        report.checks.append(CheckResult("A", "A", Severity.HIGH, False, "desc"))
        d = report.to_dict()
        assert d["target"] == "http://example.com"
        assert "risk_score" in d
        assert "checks" in d
        assert d["total"] == 1
        assert d["failed"] == 1


# ---------------------------------------------------------------------------
# APIScanner (offline — mock HTTP client)
# ---------------------------------------------------------------------------

class TestAPIScanner:
    def _scanner(self, responses: dict) -> APIScanner:
        return APIScanner(
            base_url="http://example.com",
            http_client=mock_client(responses),
        )

    def test_auth_check_included_in_report(self):
        scanner = self._scanner({"/api/me": make_resp(200)})
        report = scanner.run(check_auth=True, check_headers=False, check_versions=False)
        ids = [c.check_id for c in report.checks]
        assert "API2_BROKEN_AUTH" in ids

    def test_auth_check_401_passes(self):
        scanner = self._scanner({"/api/me": make_resp(401)})
        report = scanner.run(check_auth=True, check_headers=False, check_versions=False)
        auth = next(c for c in report.checks if c.check_id == "API2_BROKEN_AUTH")
        assert auth.passed

    def test_headers_check_included(self):
        scanner = self._scanner({"/": make_resp(200, headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
        })})
        report = scanner.run(check_auth=False, check_headers=True, check_versions=False)
        ids = [c.check_id for c in report.checks]
        assert "API8_SEC_HEADERS" in ids
        assert "API8_VERBOSE_ERRORS" in ids

    def test_versions_check_flags_200(self):
        def client(url, method="GET", headers=None, body=None):
            if "/v0" in url:
                return make_resp(200)
            return make_resp(404, url=url)
        scanner = APIScanner(base_url="http://example.com", http_client=client)
        report = scanner.run(check_auth=False, check_headers=False, check_versions=True)
        ver = next(c for c in report.checks if c.check_id == "API9_INVENTORY")
        assert not ver.passed

    def test_graphql_check_included(self):
        body = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        scanner = self._scanner({"/graphql": make_resp(200, body=body)})
        report = scanner.run(
            check_auth=False, check_headers=False, check_versions=False,
            check_graphql=True
        )
        ids = [c.check_id for c in report.checks]
        assert "GQL_INTROSPECTION" in ids
        assert "GQL_DEPTH_LIMIT" in ids

    def test_fuzz_check_included(self):
        scanner = self._scanner({"/api/items": make_resp(200, body={})})
        report = scanner.run(
            check_auth=False, check_headers=False, check_versions=False,
            check_fuzz=True, fuzz_path="/api/items"
        )
        ids = [c.check_id for c in report.checks]
        assert "FUZZ_SUMMARY" in ids

    def test_all_checks_disabled_empty_report(self):
        scanner = self._scanner({})
        report = scanner.run(
            check_auth=False, check_headers=False, check_versions=False
        )
        assert len(report.checks) == 0

    def test_report_target_set(self):
        scanner = self._scanner({})
        report = scanner.run(check_auth=False, check_headers=False, check_versions=False)
        assert report.target == "http://example.com"

    def test_base_url_trailing_slash_stripped(self):
        scanner = APIScanner(base_url="http://example.com/", http_client=mock_client({}))
        assert scanner.base_url == "http://example.com"

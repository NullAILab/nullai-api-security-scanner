# API Security Scanner

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white) ![Tests](https://img.shields.io/badge/Tests-78%20passing-brightgreen) ![License](https://img.shields.io/badge/License-MIT-green)

> **Difficulty:** Intermediate | **Language:** Python / FastAPI / Jinja2

An API vulnerability scanner targeting the OWASP API Security Top 10, GraphQL-specific weaknesses, and parameter fuzzing — all driven by an injectable HTTP client that makes every check fully testable offline.

---

## Features

| Check | OWASP ID | What It Tests |
|-------|----------|---------------|
| Broken Authentication | API2 | Unauthenticated access to protected endpoints |
| BOLA / IDOR | API1 | Cross-user object access (horizontal privilege escalation) |
| Mass Assignment | API3 | Privileged fields reflected in update responses |
| Rate Limiting | API4 | Missing 429 after repeated requests |
| Function-Level Auth | API5 | Regular users reaching admin endpoints |
| Security Headers | API8 | Missing X-Content-Type-Options, HSTS, CSP, X-Frame-Options |
| Verbose Errors | API8 | Stack traces / server banners in responses |
| Legacy Endpoints | API9 | `/v0`, `/swagger`, `/openapi.json`, `/api/debug` returning 200 |
| GraphQL Introspection | — | Full schema disclosure |
| GraphQL Depth Limit | — | Deeply nested queries accepted (DoS vector) |
| GraphQL Alias Abuse | — | Unlimited aliases per query |
| GraphQL Batch Abuse | — | Batched operations bypassing rate limits |
| SQL Injection | — | Error strings and time-based delays |
| Path Traversal | — | `/etc/passwd`, `win.ini` in responses |
| XSS / SSTI | — | Reflected payloads, `{{7*7}}` → 49 |
| SSRF | — | AWS metadata / localhost probes returning 200 |
| Integer Boundary | — | Overflow values causing 500 errors |

---

## Project Structure

```
30-api-security-scanner/
├── src/
│   ├── checks/
│   │   ├── models.py        ← MockResponse, CheckResult, ScanReport, Severity
│   │   ├── owasp_api.py     ← API1–API9 check functions
│   │   ├── graphql.py       ← GraphQL-specific checks
│   │   └── fuzzer.py        ← Payload library + response analyser
│   ├── scanner/
│   │   └── engine.py        ← APIScanner orchestrator
│   ├── api/
│   │   └── routes.py        ← FastAPI endpoints
│   ├── templates/
│   │   └── index.html       ← Dark-themed single-page UI
│   └── app.py               ← FastAPI factory
├── tests/
│   └── test_api_scanner.py  ← 78 tests, fully offline
└── requirements.txt
```

---

## Quick Start

```bash
cd src
pip install -r ../requirements.txt
uvicorn app:app --reload
# open http://localhost:8000
```

### Run a scan via API

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "check_auth": true,
    "check_headers": true,
    "check_versions": true,
    "check_graphql": false,
    "check_fuzz": false
  }'
```

### Demo endpoints (no live target needed)

```bash
# Test the auth check with a mock 200 response
curl -X POST http://localhost:8000/api/demo/auth \
  -d '{"status_code": 200}' -H "Content-Type: application/json"

# Test headers with custom mock headers
curl -X POST http://localhost:8000/api/demo/headers \
  -d '{"headers": {"X-Content-Type-Options": "nosniff"}}' \
  -H "Content-Type: application/json"

# Run fuzzing against a mock SQL error response
curl -X POST http://localhost:8000/api/demo/fuzz \
  -d '{"status_code": 200, "body": {"error": "sql syntax error"}}' \
  -H "Content-Type: application/json"

# List the full payload library
curl http://localhost:8000/api/payloads
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# 78 passed — all checks tested offline via mock HTTP client
```

---

## Architecture

All check functions are **injectable**: they accept `MockResponse` objects directly, so tests never make real network calls. The `APIScanner` engine accepts a custom `http_client` callable for the same reason.

```python
def mock_client(responses):
    def client(url, method="GET", headers=None, body=None):
        return responses.get(url, MockResponse(404))
    return client

scanner = APIScanner("http://example.com", http_client=mock_client({...}))
report = scanner.run(check_auth=True, check_headers=True)
```

---

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger API Security Labs](https://portswigger.net/web-security/api-testing)
- [GraphQL Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)

---


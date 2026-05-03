"""Shared data models for API security check results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class MockResponse:
    """Minimal response interface used by all checks — use for testing."""

    def __init__(
        self,
        status_code: int = 200,
        headers: Optional[dict] = None,
        body: Any = None,
        url: str = "http://example.com/api/v1/resource",
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        self.url = url

    def json(self) -> Any:
        return self.body if isinstance(self.body, (dict, list)) else {}

    def text(self) -> str:
        return str(self.body) if self.body else ""


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    name: str
    severity: str
    passed: bool
    description: str
    detail: str = ""
    evidence: Optional[dict] = None
    remediation: str = ""

    @property
    def status(self) -> str:
        return "PASS" if self.passed else "FAIL"


@dataclass
class ScanReport:
    target: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def failed(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]

    @property
    def passed(self) -> list[CheckResult]:
        return [c for c in self.checks if c.passed]

    @property
    def risk_score(self) -> str:
        sev_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        worst = max(
            (sev_order.get(c.severity, 0) for c in self.failed),
            default=0,
        )
        return next(
            (k for k, v in sev_order.items() if v == worst),
            "INFO",
        )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "risk_score": self.risk_score,
            "total": len(self.checks),
            "failed": len(self.failed),
            "checks": [
                {
                    "check_id": c.check_id,
                    "name": c.name,
                    "severity": c.severity,
                    "status": c.status,
                    "description": c.description,
                    "detail": c.detail,
                    "evidence": c.evidence,
                    "remediation": c.remediation,
                }
                for c in self.checks
            ],
        }

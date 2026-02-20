"""Data models used by the AEM WAF/CDN agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .privacy import maybe_redact_value, redact_structure


@dataclass(slots=True)
class AnalysisFinding:
    """Single analysis result item."""

    code: str
    severity: str
    message: str
    path: str | None = None
    rule_id: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "rule_id": self.rule_id,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class AnalysisReport:
    """Aggregated analysis report."""

    findings: list[AnalysisFinding] = field(default_factory=list)
    rule_count: int = 0
    collection_count: int = 0

    def add(
        self,
        *,
        code: str,
        severity: str,
        message: str,
        path: str | None = None,
        rule_id: str | None = None,
        recommendation: str | None = None,
    ) -> None:
        self.findings.append(
            AnalysisFinding(
                code=code,
                severity=severity,
                message=maybe_redact_value(message),
                path=maybe_redact_value(path),
                rule_id=maybe_redact_value(rule_id),
                recommendation=maybe_redact_value(recommendation),
            )
        )

    @property
    def error_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity == "warning")

    @property
    def info_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity == "info")

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "rule_count": self.rule_count,
                "collection_count": self.collection_count,
                "error_count": self.error_count,
                "warning_count": self.warning_count,
                "info_count": self.info_count,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class ParsedRequirement:
    """Deterministically parsed natural-language requirement."""

    raw_text: str
    intent: str
    params: dict[str, Any]
    confidence: float


@dataclass(slots=True)
class GenerationResult:
    """Output of generated rules and associated analysis."""

    generated_rules: list[dict[str, Any]]
    skipped_requirements: list[dict[str, Any]]
    output_config: dict[str, Any]
    analysis_report: AnalysisReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_rules": redact_structure(self.generated_rules),
            "skipped_requirements": redact_structure(self.skipped_requirements),
            "analysis_report": self.analysis_report.to_dict(),
        }

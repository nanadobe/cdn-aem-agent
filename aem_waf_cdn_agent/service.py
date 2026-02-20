"""Shared service helpers for API and MCP integrations."""

from __future__ import annotations

from typing import Any

import yaml

from .agent import AemWafCdnAgent


def parse_cdn_yaml_text(cdn_yaml: str) -> dict[str, Any]:
    """Parse YAML text and validate top-level object type."""
    try:
        loaded = yaml.safe_load(cdn_yaml) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("cdn_yaml must deserialize to a mapping/object.")
    return loaded


def to_yaml_text(config: dict[str, Any]) -> str:
    """Serialize config to normalized YAML."""
    return yaml.safe_dump(
        config,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=False,
    )


def analyze_yaml_text(cdn_yaml: str) -> dict[str, Any]:
    """Analyze YAML text and return redacted report dictionary."""
    config = parse_cdn_yaml_text(cdn_yaml)
    report = AemWafCdnAgent().analyze(config)
    return report.to_dict()


def generate_from_yaml_text(cdn_yaml: str, requirements_text: str) -> dict[str, Any]:
    """Generate rules from YAML + requirement text and return full response payload."""
    if not requirements_text.strip():
        raise ValueError("requirements_text cannot be empty.")
    config = parse_cdn_yaml_text(cdn_yaml)
    result = AemWafCdnAgent().generate_rules(config, requirements_text)
    return {
        "generated_rules_count": len(result.generated_rules),
        "skipped_requirements_count": len(result.skipped_requirements),
        "generated_rules": result.generated_rules,
        "skipped_requirements": result.skipped_requirements,
        "analysis_report": result.analysis_report.to_dict(),
        "output_cdn_yaml": to_yaml_text(result.output_config),
    }

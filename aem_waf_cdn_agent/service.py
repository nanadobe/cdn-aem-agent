"""Shared service helpers for MCP integrations."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import yaml

from .agent import AemWafCdnAgent
from .analyzer import DOC_REFERENCES
from .config import ensure_primary_rule_collection
from .mcp_features import FEATURE_PACK_DESCRIPTIONS, build_feature_pack
from .privacy import redact_text


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


def validate_yaml_text(cdn_yaml: str) -> dict[str, Any]:
    """Validate YAML syntax + semantics and return pass/fail summary."""
    report = analyze_yaml_text(cdn_yaml)
    summary = report["summary"]
    return {
        "is_valid": summary["error_count"] == 0,
        "error_count": summary["error_count"],
        "warning_count": summary["warning_count"],
        "info_count": summary["info_count"],
        "report": report,
    }


def create_report_from_yaml_text(cdn_yaml: str, *, report_format: str = "markdown") -> dict[str, Any]:
    """Create a report from YAML with markdown/json output."""
    report = analyze_yaml_text(cdn_yaml)
    normalized_format = report_format.strip().lower()
    if normalized_format == "json":
        return {"format": "json", "report": report}
    if normalized_format == "markdown":
        return {"format": "markdown", "report": _render_markdown_report(report)}
    raise ValueError("report_format must be one of: markdown, json")


def list_feature_packs() -> list[dict[str, str]]:
    """List available feature packs for MCP add_feature tool."""
    return [
        {"feature_name": name, "description": description}
        for name, description in sorted(FEATURE_PACK_DESCRIPTIONS.items())
    ]


def add_feature_pack_to_yaml_text(
    cdn_yaml: str,
    *,
    feature_name: str,
    mode: str = "safe",
) -> dict[str, Any]:
    """Add predefined rule feature pack to YAML and return updated output."""
    config = parse_cdn_yaml_text(cdn_yaml)
    collection = ensure_primary_rule_collection(config)
    existing_names = {
        str(rule["name"]).strip()
        for rule in collection.rules
        if isinstance(rule, dict) and isinstance(rule.get("name"), str)
    }

    pack_rules = build_feature_pack(feature_name, mode=mode)
    added_rules: list[str] = []
    skipped_rules: list[str] = []

    for rule in pack_rules:
        name = str(rule.get("name", "")).strip()
        if not name:
            continue
        if name in existing_names:
            skipped_rules.append(name)
            continue
        existing_names.add(name)
        collection.rules.append(deepcopy(rule))
        added_rules.append(name)

    report = AemWafCdnAgent().analyze(config)
    return {
        "feature_name": feature_name,
        "mode": mode,
        "added_rules": added_rules,
        "skipped_rules": skipped_rules,
        "analysis_report": report.to_dict(),
        "output_cdn_yaml": to_yaml_text(config),
    }


def create_custom_rule_in_yaml_text(
    cdn_yaml: str,
    *,
    rule_name: str,
    action_type: str,
    req_property: str,
    predicate: str,
    predicate_value: str,
    tier_scope: str = "publish",
    alert: bool = False,
) -> dict[str, Any]:
    """Create a custom Adobe-syntax rule and append to YAML config."""
    normalized_name = _normalize_rule_name(rule_name)
    normalized_action = action_type.strip().lower()
    if normalized_action not in {"allow", "block", "log"}:
        raise ValueError("action_type must be one of: allow, block, log")

    tiers = [entry.strip().lower() for entry in tier_scope.split(",") if entry.strip()]
    if not tiers:
        tiers = ["publish"]

    config = parse_cdn_yaml_text(cdn_yaml)
    collection = ensure_primary_rule_collection(config)
    existing_names = {
        str(rule["name"]).strip()
        for rule in collection.rules
        if isinstance(rule, dict) and isinstance(rule.get("name"), str)
    }
    rule_name_final = _dedupe_name(normalized_name, existing_names)

    condition: dict[str, Any] = {"reqProperty": req_property.strip(), predicate.strip(): predicate_value}
    custom_rule: dict[str, Any] = {
        "name": rule_name_final,
        "when": {
            "allOf": [
                {"reqProperty": "tier", "in": tiers},
                condition,
            ]
        },
        "action": {"type": normalized_action},
    }
    if alert:
        custom_rule["action"]["alert"] = True

    collection.rules.append(custom_rule)
    report = AemWafCdnAgent().analyze(config)
    return {
        "created_rule_name": rule_name_final,
        "analysis_report": report.to_dict(),
        "output_cdn_yaml": to_yaml_text(config),
    }


def list_mcp_tool_capabilities() -> list[dict[str, str]]:
    """List tool capabilities exposed via MCP server."""
    return [
        {
            "tool": "analyze_cdn_yaml",
            "purpose": "Run full analysis and return findings report.",
        },
        {
            "tool": "analyse_cdn_yaml",
            "purpose": "Alias for analyze_cdn_yaml.",
        },
        {
            "tool": "validate_cdn_yaml",
            "purpose": "Return pass/fail validation summary and report.",
        },
        {
            "tool": "create_analysis_report",
            "purpose": "Generate markdown or JSON report from config.",
        },
        {
            "tool": "create_rules_from_requirements",
            "purpose": "Generate rules from natural-language requirements.",
        },
        {
            "tool": "generate_cdn_rules",
            "purpose": "Alias for create_rules_from_requirements.",
        },
        {
            "tool": "add_feature_pack",
            "purpose": "Insert predefined starter rules by feature name.",
        },
        {
            "tool": "add_feature",
            "purpose": "Alias for add_feature_pack.",
        },
        {
            "tool": "create_custom_rule",
            "purpose": "Create and append one custom rule from structured inputs.",
        },
        {
            "tool": "list_feature_packs",
            "purpose": "Show supported feature packs.",
        },
        {
            "tool": "get_adobe_reference_docs",
            "purpose": "Return documentation URLs used as source of truth.",
        },
    ]


def get_reference_docs() -> list[str]:
    """Return source-of-truth documentation URLs."""
    return list(DOC_REFERENCES)


def _render_markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# AEM CDN/WAF Analysis Report",
        "",
        f"- Rules: {summary['rule_count']}",
        f"- Collections: {summary['collection_count']}",
        f"- Errors: {summary['error_count']}",
        f"- Warnings: {summary['warning_count']}",
        f"- Info: {summary['info_count']}",
        "",
        "## Findings",
    ]
    findings = report.get("findings", [])
    if not findings:
        lines.append("- No findings.")
        return "\n".join(lines)

    for finding in findings:
        severity = str(finding.get("severity", "info")).upper()
        code = str(finding.get("code", "UNKNOWN"))
        message = redact_text(str(finding.get("message", "")))
        path = finding.get("path")
        rule_id = finding.get("rule_id")
        lines.append(f"- [{severity}] {code}: {message}")
        if path:
            lines.append(f"  - path: {redact_text(str(path))}")
        if rule_id:
            lines.append(f"  - rule: {redact_text(str(rule_id))}")
        recommendation = finding.get("recommendation")
        if recommendation:
            lines.append(f"  - recommendation: {redact_text(str(recommendation))}")
    return "\n".join(lines)


def _normalize_rule_name(value: str) -> str:
    filtered = "".join(char.lower() if char.isalnum() else "-" for char in value.strip())
    compact = "-".join(part for part in filtered.split("-") if part)
    return compact[:64] if compact else "custom-rule"


def _dedupe_name(name: str, existing: set[str]) -> str:
    if name not in existing:
        return name
    counter = 2
    while True:
        candidate = f"{name}-{counter}"[:64]
        if candidate not in existing:
            return candidate
        counter += 1

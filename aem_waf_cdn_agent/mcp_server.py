"""MCP server exposing the AEM WAF/CDN agent tools."""

from __future__ import annotations

from .service import (
    add_feature_pack_to_yaml_text,
    analyze_yaml_text,
    create_custom_rule_in_yaml_text,
    create_report_from_yaml_text,
    generate_from_yaml_text,
    get_reference_docs,
    list_feature_packs as list_feature_packs_service,
    list_mcp_tool_capabilities,
    validate_yaml_text,
)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - depends on environment extras
    FastMCP = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


if FastMCP is not None:
    mcp = FastMCP("aem-waf-cdn-agent")

    @mcp.tool()
    def analyze_cdn_yaml(cdn_yaml: str) -> dict:
        """Analyze a cdn.yaml string and return redacted findings."""
        return analyze_yaml_text(cdn_yaml)

    @mcp.tool()
    def analyse_cdn_yaml(cdn_yaml: str) -> dict:
        """Alias for analyze_cdn_yaml for UK spelling."""
        return analyze_yaml_text(cdn_yaml)

    @mcp.tool()
    def validate_cdn_yaml(cdn_yaml: str) -> dict:
        """Validate config and return pass/fail plus full report."""
        return validate_yaml_text(cdn_yaml)

    @mcp.tool()
    def create_analysis_report(cdn_yaml: str, report_format: str = "markdown") -> dict:
        """Create markdown/json analysis report from YAML config."""
        return create_report_from_yaml_text(cdn_yaml, report_format=report_format)

    @mcp.tool()
    def create_rules_from_requirements(cdn_yaml: str, requirements_text: str) -> dict:
        """Generate/update traffic filter rules from natural language."""
        return generate_from_yaml_text(cdn_yaml, requirements_text)

    @mcp.tool()
    def generate_cdn_rules(cdn_yaml: str, requirements_text: str) -> dict:
        """Backward-compatible alias for create_rules_from_requirements."""
        return generate_from_yaml_text(cdn_yaml, requirements_text)

    @mcp.tool()
    def add_feature_pack(cdn_yaml: str, feature_name: str, mode: str = "safe") -> dict:
        """Add predefined feature pack rules into YAML config."""
        return add_feature_pack_to_yaml_text(
            cdn_yaml, feature_name=feature_name, mode=mode
        )

    @mcp.tool()
    def add_feature(cdn_yaml: str, feature_name: str, mode: str = "safe") -> dict:
        """Alias for add_feature_pack."""
        return add_feature_pack_to_yaml_text(
            cdn_yaml, feature_name=feature_name, mode=mode
        )

    @mcp.tool()
    def create_custom_rule(
        cdn_yaml: str,
        rule_name: str,
        action_type: str,
        req_property: str,
        predicate: str,
        predicate_value: str,
        tier_scope: str = "publish",
        alert: bool = False,
    ) -> dict:
        """Create and append a custom Adobe-syntax rule."""
        return create_custom_rule_in_yaml_text(
            cdn_yaml,
            rule_name=rule_name,
            action_type=action_type,
            req_property=req_property,
            predicate=predicate,
            predicate_value=predicate_value,
            tier_scope=tier_scope,
            alert=alert,
        )

    @mcp.tool()
    def list_feature_packs() -> list[dict[str, str]]:
        """List available feature packs for add_feature_pack."""
        return list_feature_packs_service()

    @mcp.tool()
    def list_tool_capabilities() -> list[dict[str, str]]:
        """List available MCP tool capabilities and purpose."""
        return list_mcp_tool_capabilities()

    @mcp.tool()
    def get_adobe_reference_docs() -> list[str]:
        """Return Adobe public documentation URLs used by this MCP agent."""
        return get_reference_docs()


def main() -> None:
    if FastMCP is None:
        raise SystemExit(
            "MCP runtime is unavailable. Install project dependencies to use MCP "
            f"server: {_IMPORT_ERROR!r}"
        )
    mcp.run()


if __name__ == "__main__":
    main()

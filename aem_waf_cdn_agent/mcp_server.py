"""MCP server exposing the AEM WAF/CDN agent tools."""

from __future__ import annotations

from .analyzer import DOC_REFERENCES
from .service import analyze_yaml_text, generate_from_yaml_text

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
    def generate_cdn_rules(cdn_yaml: str, requirements_text: str) -> dict:
        """Generate/update traffic filter rules from natural language."""
        return generate_from_yaml_text(cdn_yaml, requirements_text)

    @mcp.tool()
    def get_adobe_reference_docs() -> list[str]:
        """Return Adobe public documentation URLs used by this agent."""
        return list(DOC_REFERENCES)


def main() -> None:
    if FastMCP is None:
        raise SystemExit(
            "MCP runtime is unavailable. Install project dependencies to use MCP "
            f"server: {_IMPORT_ERROR!r}"
        )
    mcp.run()


if __name__ == "__main__":
    main()

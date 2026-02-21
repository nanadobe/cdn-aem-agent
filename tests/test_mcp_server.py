import unittest

import aem_waf_cdn_agent.mcp_server as mcp_server


class McpServerTests(unittest.TestCase):
    def test_mcp_tools_are_available(self) -> None:
        self.assertTrue(hasattr(mcp_server, "analyze_cdn_yaml"))
        self.assertTrue(hasattr(mcp_server, "analyse_cdn_yaml"))
        self.assertTrue(hasattr(mcp_server, "validate_cdn_yaml"))
        self.assertTrue(hasattr(mcp_server, "create_analysis_report"))
        self.assertTrue(hasattr(mcp_server, "create_rules_from_requirements"))
        self.assertTrue(hasattr(mcp_server, "generate_cdn_rules"))
        self.assertTrue(hasattr(mcp_server, "add_feature_pack"))
        self.assertTrue(hasattr(mcp_server, "add_feature"))
        self.assertTrue(hasattr(mcp_server, "create_custom_rule"))
        self.assertTrue(hasattr(mcp_server, "list_feature_packs"))
        self.assertTrue(hasattr(mcp_server, "list_tool_capabilities"))
        self.assertTrue(hasattr(mcp_server, "get_adobe_reference_docs"))


if __name__ == "__main__":
    unittest.main()

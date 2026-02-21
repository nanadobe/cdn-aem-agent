import unittest
from pathlib import Path

from aem_waf_cdn_agent.service import (
    add_feature_pack_to_yaml_text,
    analyze_yaml_text,
    create_custom_rule_in_yaml_text,
    create_report_from_yaml_text,
    generate_from_yaml_text,
    list_feature_packs,
    validate_yaml_text,
)


class ServiceTests(unittest.TestCase):
    def test_analyze_yaml_text_with_public_fixture(self) -> None:
        fixture = (
            Path(__file__).parent
            / "data"
            / "public_docs_examples"
            / "adobe-recommended-standard-and-waf.yaml"
        )
        response = analyze_yaml_text(fixture.read_text(encoding="utf-8"))
        self.assertIn("summary", response)
        self.assertEqual(response["summary"]["error_count"], 0)

    def test_generate_from_yaml_text(self) -> None:
        input_yaml = """\
kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules: []
"""
        requirements = "Block access to /system/console*"
        response = generate_from_yaml_text(input_yaml, requirements)

        self.assertEqual(response["generated_rules_count"], 1)
        self.assertIn("output_cdn_yaml", response)
        self.assertIn("trafficFilters", response["output_cdn_yaml"])

    def test_service_rejects_invalid_yaml(self) -> None:
        with self.assertRaises(ValueError):
            analyze_yaml_text("kind: [unbalanced")

    def test_validate_yaml_text(self) -> None:
        fixture = (
            Path(__file__).parent
            / "data"
            / "public_docs_examples"
            / "adobe-recommended-standard-and-waf.yaml"
        )
        result = validate_yaml_text(fixture.read_text(encoding="utf-8"))
        self.assertTrue(result["is_valid"])
        self.assertEqual(result["error_count"], 0)

    def test_create_markdown_report(self) -> None:
        fixture = (
            Path(__file__).parent
            / "data"
            / "public_docs_examples"
            / "tutorial-request-logging.yaml"
        )
        result = create_report_from_yaml_text(
            fixture.read_text(encoding="utf-8"), report_format="markdown"
        )
        self.assertEqual(result["format"], "markdown")
        self.assertIn("AEM CDN/WAF Analysis Report", result["report"])

    def test_add_feature_pack(self) -> None:
        input_yaml = """\
kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules: []
"""
        result = add_feature_pack_to_yaml_text(
            input_yaml, feature_name="standard_recommended"
        )
        self.assertGreaterEqual(len(result["added_rules"]), 3)
        self.assertIn("output_cdn_yaml", result)

    def test_create_custom_rule(self) -> None:
        input_yaml = """\
kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules: []
"""
        result = create_custom_rule_in_yaml_text(
            input_yaml,
            rule_name="Block System Console",
            action_type="block",
            req_property="path",
            predicate="like",
            predicate_value="/system/console*",
            tier_scope="publish",
            alert=False,
        )
        self.assertIn("created_rule_name", result)
        self.assertIn("output_cdn_yaml", result)

    def test_list_feature_packs(self) -> None:
        packs = list_feature_packs()
        names = {item["feature_name"] for item in packs}
        self.assertIn("standard_recommended", names)
        self.assertIn("waf_recommended", names)
        self.assertIn("auth_monitoring", names)


if __name__ == "__main__":
    unittest.main()

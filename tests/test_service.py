import unittest
from pathlib import Path

from aem_waf_cdn_agent.service import analyze_yaml_text, generate_from_yaml_text


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


if __name__ == "__main__":
    unittest.main()

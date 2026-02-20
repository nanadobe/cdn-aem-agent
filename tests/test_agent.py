import tempfile
import unittest
from pathlib import Path

from aem_waf_cdn_agent.agent import AemWafCdnAgent
from aem_waf_cdn_agent.analyzer import analyze_config
from aem_waf_cdn_agent.config import load_yaml


class AnalyzerTests(unittest.TestCase):
    def test_analyzer_detects_documented_syntax_problems(self) -> None:
        config = {
            "kind": "CDN",
            "version": "1",
            "data": {
                "trafficFilters": {
                    "rules": [
                        {
                            "name": "bad rule name",
                            "when": {"reqProperty": "clientIp", "matches": "^10\\."},
                            "action": {"type": "drop"},
                            "rateLimit": {"limit": 5, "window": 3, "count": "burst"},
                        }
                    ]
                }
            },
        }

        report = analyze_config(config)
        finding_codes = {finding.code for finding in report.findings}

        self.assertIn("INVALID_RULE_NAME_FORMAT", finding_codes)
        self.assertIn("INVALID_CLIENT_IP_PREDICATE", finding_codes)
        self.assertIn("UNSUPPORTED_ACTION_TYPE", finding_codes)
        self.assertIn("RATE_LIMIT_LIMIT_RANGE", finding_codes)
        self.assertIn("INVALID_RATE_LIMIT_WINDOW", finding_codes)
        self.assertIn("INVALID_RATE_LIMIT_COUNT", finding_codes)
        self.assertGreaterEqual(report.error_count, 4)

    def test_analyzer_redacts_sensitive_literals_in_findings(self) -> None:
        config = {
            "kind": "CDN",
            "version": "1",
            "data": {
                "trafficFilters": {
                    "rules": [
                        {
                            "name": "invalid-client-ip",
                            "when": {"reqProperty": "clientIp", "equals": "203.0.113.999"},
                            "action": {"type": "block"},
                        }
                    ]
                }
            },
        }
        report = analyze_config(config)
        combined_messages = "\n".join(item.message for item in report.findings)
        self.assertNotIn("203.0.113.999", combined_messages)
        self.assertIn("<redacted-ip>", combined_messages)


class PublicDocsFixtureTests(unittest.TestCase):
    def test_public_docs_recommended_fixture_has_no_errors(self) -> None:
        config = load_yaml(
            Path(__file__).parent
            / "data"
            / "public_docs_examples"
            / "adobe-recommended-standard-and-waf.yaml"
        )
        report = analyze_config(config)
        self.assertEqual(report.error_count, 0)

    def test_public_tutorial_fixture_has_no_errors(self) -> None:
        config = load_yaml(
            Path(__file__).parent
            / "data"
            / "public_docs_examples"
            / "tutorial-request-logging.yaml"
        )
        report = analyze_config(config)
        self.assertEqual(report.error_count, 0)


class GenerationTests(unittest.TestCase):
    def test_generation_from_requirements_uses_adobe_syntax(self) -> None:
        config = {
            "kind": "CDN",
            "version": "1",
            "data": {"trafficFilters": {"rules": []}},
        }
        requirements = "\n".join(
            [
                "Block access to /system/console*",
                "Rate limit /libs/granite/core/content/login to 600 requests per minute",
                "Allow traffic from 10.0.0.0/8",
                "Do something smart with bots and AI threat models and secret=abc123xyz987",
            ]
        )

        agent = AemWafCdnAgent()
        result = agent.generate_rules(config, requirements)

        self.assertEqual(len(result.generated_rules), 3)
        self.assertEqual(len(result.skipped_requirements), 1)
        self.assertIn("name", result.generated_rules[0])
        self.assertIn("when", result.generated_rules[0])
        self.assertIn("action", result.generated_rules[0])
        self.assertNotIn("abc123xyz987", result.skipped_requirements[0]["requirement"])
        self.assertEqual(result.analysis_report.error_count, 0)
        rate_limits = [rule for rule in result.generated_rules if "rateLimit" in rule]
        self.assertEqual(rate_limits[0]["rateLimit"]["limit"], 10)
        self.assertEqual(rate_limits[0]["action"]["type"], "block")

    def test_generation_writes_output_file(self) -> None:
        requirements = "Block access to /system/console*"
        source_yaml = """\
kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules:
      - name: existing-rule
        when:
          reqProperty: path
          like: /crx*
        action:
          type: block
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cdn.yaml"
            output = Path(temp_dir) / "cdn.generated.yaml"
            source.write_text(source_yaml, encoding="utf-8")

            agent = AemWafCdnAgent()
            result = agent.generate_from_files(
                cdn_yaml_path=source,
                requirements_text=requirements,
                output_yaml_path=output,
            )
            self.assertEqual(len(result.generated_rules), 1)

            written = load_yaml(output)
            self.assertIn("data", written)
            self.assertIn("trafficFilters", written["data"])
            self.assertIn("rules", written["data"]["trafficFilters"])
            self.assertGreaterEqual(len(written["data"]["trafficFilters"]["rules"]), 2)


if __name__ == "__main__":
    unittest.main()

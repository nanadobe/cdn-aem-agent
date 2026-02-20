import tempfile
import unittest
from pathlib import Path

from aem_waf_cdn_agent.agent import AemWafCdnAgent
from aem_waf_cdn_agent.analyzer import analyze_config
from aem_waf_cdn_agent.config import load_yaml


class AnalyzerTests(unittest.TestCase):
    def test_analyzer_detects_schema_and_action_problems(self) -> None:
        config = {
            "rules": [
                {
                    "id": "dup-rule",
                    "action": "block",
                    "priority": 10,
                    "match": {"path": "/system/console*"},
                },
                {
                    "id": "dup-rule",
                    "action": "drop",
                    "priority": "high",
                    "match": {"path": "/crx*"},
                },
                {"id": "allow-all", "action": "allow"},
            ]
        }

        report = analyze_config(config)
        finding_codes = {finding.code for finding in report.findings}

        self.assertIn("DUPLICATE_RULE_ID", finding_codes)
        self.assertIn("UNSUPPORTED_RULE_ACTION", finding_codes)
        self.assertIn("INVALID_RULE_PRIORITY", finding_codes)
        self.assertIn("BROAD_ALLOW_RULE", finding_codes)
        self.assertGreaterEqual(report.error_count, 2)

    def test_analyzer_requires_sensitive_endpoint_coverage(self) -> None:
        config = {
            "rules": [
                {
                    "id": "only-console-block",
                    "action": "block",
                    "priority": 10,
                    "match": {"path": "/system/console*"},
                }
            ]
        }
        report = analyze_config(config)
        sensitive_findings = [
            finding
            for finding in report.findings
            if finding.code == "MISSING_AEM_SENSITIVE_ENDPOINT_GUARD"
        ]
        self.assertTrue(
            any("/etc/packages" in finding.message for finding in sensitive_findings)
        )
        self.assertTrue(
            any("/bin/querybuilder" in finding.message for finding in sensitive_findings)
        )


class GenerationTests(unittest.TestCase):
    def test_generation_from_requirements(self) -> None:
        config = {
            "rules": [
                {
                    "id": "existing",
                    "action": "block",
                    "priority": 100,
                    "match": {"path": "/crx*"},
                }
            ]
        }
        requirements = "\n".join(
            [
                "Block access to /system/console*",
                "Rate limit /libs/granite/core/content/login to 45 requests per minute",
                "Allow traffic from 10.0.0.0/8",
                "Do something smart with bots and AI threat models",
            ]
        )

        agent = AemWafCdnAgent()
        result = agent.generate_rules(config, requirements)

        self.assertEqual(len(result.generated_rules), 3)
        self.assertEqual(len(result.skipped_requirements), 1)
        self.assertEqual(result.generated_rules[0]["priority"], 110)
        self.assertEqual(result.generated_rules[1]["priority"], 120)
        self.assertEqual(result.generated_rules[2]["priority"], 130)
        rate_limits = [
            rule for rule in result.generated_rules if rule.get("action") == "rate_limit"
        ]
        self.assertEqual(rate_limits[0]["limit_per_minute"], 45)

    def test_generation_writes_output_file(self) -> None:
        requirements = "Block access to /system/console*"
        source_yaml = """\
rules:
  - id: existing
    action: block
    priority: 100
    match:
      path: /crx*
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
            self.assertIn("rules", written)
            self.assertGreaterEqual(len(written["rules"]), 2)


if __name__ == "__main__":
    unittest.main()

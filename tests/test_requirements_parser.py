import unittest

from aem_waf_cdn_agent.requirements_parser import parse_requirements


class RequirementParserTests(unittest.TestCase):
    def test_parser_understands_country_names_and_codes(self) -> None:
        parsed = parse_requirements("Block traffic from countries china, ru, and Iran")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].intent, "block_country")
        self.assertEqual(parsed[0].params["country_codes"], ["CN", "IR", "RU"])

    def test_parser_understands_method_restrictions(self) -> None:
        parsed = parse_requirements("Restrict methods to GET and POST for /content/*")
        self.assertEqual(parsed[0].intent, "allow_methods_path")
        self.assertEqual(parsed[0].params["path"], "/content/*")
        self.assertEqual(parsed[0].params["methods"], ["GET", "POST"])


if __name__ == "__main__":
    unittest.main()

"""Command line interface for the AEM WAF/CDN agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import AemWafCdnAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aem-waf-cdn-agent",
        description=(
            "Analyze AEM WAF/CDN rule configuration and generate rules from "
            "natural-language requirements."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze", help="Validate and analyze an existing cdn.yaml"
    )
    analyze.add_argument("--cdn-yaml", required=True, help="Path to cdn.yaml")
    analyze.add_argument(
        "--report-json",
        help="Optional output JSON path for detailed findings report.",
    )
    analyze.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help="Return non-zero exit if warnings are present.",
    )

    generate = subparsers.add_parser(
        "generate",
        help="Generate rules from natural-language requirements and write YAML output.",
    )
    generate.add_argument("--cdn-yaml", required=True, help="Path to source cdn.yaml")
    generate.add_argument(
        "--requirements-file",
        help="Text file containing one or more requirements (one per line).",
    )
    generate.add_argument(
        "--requirement",
        action="append",
        default=[],
        help="Inline requirement text; can be repeated.",
    )
    generate.add_argument(
        "--output-cdn-yaml",
        help="Destination path for generated YAML (ignored when --inplace is used).",
    )
    generate.add_argument(
        "--report-json",
        help="Optional output JSON path for generation + analysis report.",
    )
    generate.add_argument(
        "--inplace",
        action="store_true",
        help="Write generated output back into the source cdn.yaml.",
    )
    generate.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help="Return non-zero exit if warnings are present after generation.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    agent = AemWafCdnAgent()

    if args.command == "analyze":
        report = agent.analyze_file(args.cdn_yaml)
        print(_render_summary(report))
        _print_findings(report)
        if args.report_json:
            _write_json(args.report_json, report.to_dict())
        return _status_code(report.error_count, report.warning_count, args.fail_on_warnings)

    requirements_text = _build_requirements_text(
        requirements_file=args.requirements_file,
        inline_requirements=args.requirement,
    )
    if not requirements_text.strip():
        parser.error("No requirements provided. Use --requirements-file and/or --requirement.")

    result = agent.generate_from_files(
        cdn_yaml_path=args.cdn_yaml,
        requirements_text=requirements_text,
        output_yaml_path=args.output_cdn_yaml,
        inplace=args.inplace,
    )

    print(f"Generated {len(result.generated_rules)} rules.")
    if result.skipped_requirements:
        print(f"Skipped {len(result.skipped_requirements)} requirements:")
        for skipped in result.skipped_requirements:
            print(f"  - {skipped['requirement']} ({skipped['reason']})")

    print(_render_summary(result.analysis_report))
    _print_findings(result.analysis_report)

    if args.report_json:
        payload = result.to_dict()
        _write_json(args.report_json, payload)

    return _status_code(
        result.analysis_report.error_count,
        result.analysis_report.warning_count,
        args.fail_on_warnings,
    )


def _build_requirements_text(
    *, requirements_file: str | None, inline_requirements: list[str]
) -> str:
    sections: list[str] = []
    if requirements_file:
        content = Path(requirements_file).read_text(encoding="utf-8")
        sections.append(content)
    if inline_requirements:
        sections.append("\n".join(inline_requirements))
    return "\n".join(sections)


def _write_json(path: str | Path, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _render_summary(report) -> str:
    return (
        f"Rules: {report.rule_count}, Collections: {report.collection_count}, "
        f"Errors: {report.error_count}, Warnings: {report.warning_count}, "
        f"Info: {report.info_count}"
    )


def _print_findings(report) -> None:
    if not report.findings:
        print("No findings.")
        return
    for finding in report.findings:
        location = f" path={finding.path}" if finding.path else ""
        rule = f" rule={finding.rule_id}" if finding.rule_id else ""
        print(
            f"[{finding.severity.upper()}] {finding.code}: "
            f"{finding.message}{location}{rule}"
        )
        if finding.recommendation:
            print(f"  Recommendation: {finding.recommendation}")


def _status_code(error_count: int, warning_count: int, fail_on_warnings: bool) -> int:
    if error_count > 0:
        return 2
    if fail_on_warnings and warning_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""High-level orchestration for AEM WAF/CDN analysis and generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzer import analyze_config
from .config import dump_yaml, load_yaml
from .generator import generate_rules_from_requirements
from .models import AnalysisReport, GenerationResult


class AemWafCdnAgent:
    """Agent for validating and generating AEM WAF/CDN rules."""

    def analyze(self, config: dict[str, Any]) -> AnalysisReport:
        """Analyze already-loaded configuration."""
        return analyze_config(config)

    def analyze_file(self, cdn_yaml_path: str | Path) -> AnalysisReport:
        """Load and analyze a cdn.yaml file."""
        config = load_yaml(cdn_yaml_path)
        return self.analyze(config)

    def generate_rules(
        self, config: dict[str, Any], requirements_text: str
    ) -> GenerationResult:
        """Generate rules from natural language and analyze resulting config."""
        generated_rules, skipped = generate_rules_from_requirements(
            config, requirements_text
        )
        report = self.analyze(config)
        return GenerationResult(
            generated_rules=generated_rules,
            skipped_requirements=skipped,
            output_config=config,
            analysis_report=report,
        )

    def generate_from_files(
        self,
        *,
        cdn_yaml_path: str | Path,
        requirements_text: str,
        output_yaml_path: str | Path | None = None,
        inplace: bool = False,
    ) -> GenerationResult:
        """Load config, generate rules, and write resulting YAML."""
        config = load_yaml(cdn_yaml_path)
        result = self.generate_rules(config, requirements_text)

        source_path = Path(cdn_yaml_path)
        if inplace:
            destination = source_path
        elif output_yaml_path is not None:
            destination = Path(output_yaml_path)
        else:
            destination = source_path.with_name(f"{source_path.stem}.generated.yaml")

        dump_yaml(destination, result.output_config)
        return result

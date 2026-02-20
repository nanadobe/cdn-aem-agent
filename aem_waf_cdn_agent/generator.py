"""Rule generation from parsed natural-language requirements."""

from __future__ import annotations

import math
import re
from typing import Any

from .config import ensure_primary_rule_collection, extract_rule_collections
from .models import ParsedRequirement
from .privacy import redact_requirement_text
from .requirements_parser import parse_requirements


def generate_rules_from_requirements(
    config: dict[str, Any], requirements_text: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Generate rules and mutate config in-place."""
    _ensure_top_level_structure(config)
    parsed = parse_requirements(requirements_text)
    generated_rules: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    target_collection = ensure_primary_rule_collection(config)
    existing_names = _collect_existing_names(config)

    for item in parsed:
        if item.intent == "unknown":
            skipped.append(
                {
                    "requirement": redact_requirement_text(item.raw_text),
                    "reason": "No deterministic parser matched this requirement.",
                }
            )
            continue

        rule = _build_rule(item=item, existing_names=existing_names)
        if rule is None:
            skipped.append(
                {
                    "requirement": redact_requirement_text(item.raw_text),
                    "reason": "Parsed requirement did not have enough parameters.",
                }
            )
            continue

        existing_names.add(rule["name"])
        generated_rules.append(rule)
        target_collection.rules.append(rule)

    return generated_rules, skipped


def _build_rule(
    *, item: ParsedRequirement, existing_names: set[str]
) -> dict[str, Any] | None:
    params = item.params
    intent = item.intent

    if intent == "block_path":
        path = params.get("path")
        if not isinstance(path, str):
            return None
        return _base_rule(
            existing_names=existing_names,
            action="block",
            intent=intent,
            when=_path_tier_condition(path, tiers=["publish"]),
            name_hint=path,
        )

    if intent == "allow_path":
        path = params.get("path")
        if not isinstance(path, str):
            return None
        return _base_rule(
            existing_names=existing_names,
            action="allow",
            intent=intent,
            when=_path_tier_condition(path, tiers=["publish"]),
            name_hint=path,
        )

    if intent == "rate_limit_path":
        path = params.get("path")
        limit = params.get("limit")
        unit = params.get("limit_unit")
        if not isinstance(path, str) or not isinstance(limit, int) or not isinstance(unit, str):
            return None
        rate_limit_per_second = _to_rate_limit_per_second(limit, unit)
        return _base_rule(
            existing_names=existing_names,
            action="rate_limit",
            intent=intent,
            when=_path_tier_condition(path, tiers=["publish"]),
            name_hint=f"{path}-{rate_limit_per_second}",
            rate_limit={
                "limit": rate_limit_per_second,
                "window": 10,
                "penalty": 300,
                "count": "all",
                "groupBy": [{"reqProperty": "clientIp"}],
            },
        )

    if intent == "block_ip":
        cidrs = params.get("ip_cidrs")
        if not isinstance(cidrs, list) or not cidrs:
            return None
        return _base_rule(
            existing_names=existing_names,
            action="block",
            intent=intent,
            when=_client_ip_condition(cidrs, tiers=["author", "publish"]),
            name_hint="-".join(cidrs),
        )

    if intent == "allow_ip":
        cidrs = params.get("ip_cidrs")
        if not isinstance(cidrs, list) or not cidrs:
            return None
        return _base_rule(
            existing_names=existing_names,
            action="allow",
            intent=intent,
            when=_client_ip_condition(cidrs, tiers=["author", "publish"]),
            name_hint="-".join(cidrs),
        )

    if intent == "block_country":
        countries = params.get("country_codes")
        if not isinstance(countries, list) or not countries:
            return None
        return _base_rule(
            existing_names=existing_names,
            action="block",
            intent=intent,
            when=_client_country_condition(countries, tiers=["author", "publish"]),
            name_hint="-".join(countries),
        )

    if intent == "allow_country":
        countries = params.get("country_codes")
        if not isinstance(countries, list) or not countries:
            return None
        return _base_rule(
            existing_names=existing_names,
            action="allow",
            intent=intent,
            when=_client_country_condition(countries, tiers=["author", "publish"]),
            name_hint="-".join(countries),
        )

    if intent == "allow_methods_path":
        path = params.get("path")
        methods = params.get("methods")
        if not isinstance(path, str) or not isinstance(methods, list) or not methods:
            return None
        method_values = sorted({method.upper() for method in methods if isinstance(method, str)})
        if not method_values:
            return None
        return _base_rule(
            existing_names=existing_names,
            action="block",
            intent=intent,
            when={
                "allOf": [
                    _path_predicate(path),
                    {"reqProperty": "method", "notIn": method_values},
                    {"reqProperty": "tier", "in": ["publish"]},
                ]
            },
            name_hint=f"{path}-{'-'.join(method_values)}",
        )

    if intent == "require_header_path":
        path = params.get("path")
        header = params.get("header")
        value = params.get("header_value")
        if not isinstance(path, str) or not isinstance(header, str):
            return None
        predicate = (
            {"reqHeader": header, "exists": False}
            if value in {None, "required"}
            else {"reqHeader": header, "doesNotEqual": str(value)}
        )
        return _base_rule(
            existing_names=existing_names,
            action="block",
            intent=intent,
            when={
                "allOf": [
                    _path_predicate(path),
                    predicate,
                    {"reqProperty": "tier", "in": ["publish"]},
                ]
            },
            name_hint=f"{path}-{header}",
        )

    if intent == "challenge_path":
        return None

    return None


def _base_rule(
    *,
    existing_names: set[str],
    action: str,
    intent: str,
    when: dict[str, Any] | str,
    name_hint: str,
    rate_limit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_name = _slugify(f"{action}-{intent}-{name_hint}")
    rule_name = _next_rule_name(existing_names, normalized_name)
    if action == "rate_limit":
        rule = {
            "name": rule_name,
            "when": when,
            "rateLimit": rate_limit,
            "action": {"type": "block", "alert": True},
        }
    else:
        rule = {
            "name": rule_name,
            "when": when,
            "action": {"type": action},
        }
    return rule


def _ensure_top_level_structure(config: dict[str, Any]) -> None:
    if "kind" not in config:
        config["kind"] = "CDN"
    if "version" not in config:
        config["version"] = "1"
    data = config.get("data")
    if not isinstance(data, dict):
        data = {}
        config["data"] = data
    traffic_filters = data.get("trafficFilters")
    if not isinstance(traffic_filters, dict):
        traffic_filters = {}
        data["trafficFilters"] = traffic_filters
    if "rules" not in traffic_filters or not isinstance(traffic_filters.get("rules"), list):
        traffic_filters["rules"] = []


def _path_tier_condition(path: str, *, tiers: list[str]) -> dict[str, Any]:
    return {"allOf": [_path_predicate(path), {"reqProperty": "tier", "in": tiers}]}


def _path_predicate(path: str) -> dict[str, Any]:
    if "*" in path:
        return {"reqProperty": "path", "like": path}
    return {"reqProperty": "path", "equals": path}


def _client_ip_condition(cidrs: list[str], *, tiers: list[str]) -> dict[str, Any]:
    predicate_key = "in" if len(cidrs) > 1 else "equals"
    predicate_value: Any = cidrs if len(cidrs) > 1 else cidrs[0]
    return {
        "allOf": [
            {"reqProperty": "tier", "in": tiers},
            {"reqProperty": "clientIp", predicate_key: predicate_value},
        ]
    }


def _client_country_condition(countries: list[str], *, tiers: list[str]) -> dict[str, Any]:
    return {
        "allOf": [
            {"reqProperty": "tier", "in": tiers},
            {"reqProperty": "clientCountry", "in": countries},
        ]
    }


def _to_rate_limit_per_second(value: int, unit: str) -> int:
    normalized = unit.lower()
    if normalized.startswith("second"):
        return max(10, min(10000, value))
    # Adobe syntax supports per-second limits; convert minute to second conservatively.
    converted = math.ceil(value / 60)
    return max(10, min(10000, converted))


def _collect_existing_names(config: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for collection in extract_rule_collections(config):
        for rule in collection.rules:
            if not isinstance(rule, dict):
                continue
            candidate = rule.get("name")
            if isinstance(candidate, str) and candidate.strip():
                values.add(candidate.strip())
    return values


def _next_rule_name(existing_names: set[str], base: str) -> str:
    candidate = base[:64] if len(base) > 64 else base
    if candidate not in existing_names:
        return candidate
    counter = 2
    while True:
        fallback = f"{candidate}-{counter}"
        trimmed = fallback[:64]
        if trimmed not in existing_names:
            return trimmed
        counter += 1


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return normalized or "rule"

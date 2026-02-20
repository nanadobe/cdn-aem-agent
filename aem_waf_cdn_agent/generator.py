"""Rule generation from parsed natural-language requirements."""

from __future__ import annotations

import re
from typing import Any

from .config import ensure_primary_rule_collection, extract_rule_collections
from .models import ParsedRequirement
from .requirements_parser import parse_requirements


def generate_rules_from_requirements(
    config: dict[str, Any], requirements_text: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Generate rules and mutate config in-place."""
    parsed = parse_requirements(requirements_text)
    generated_rules: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    target_collection = ensure_primary_rule_collection(config)
    existing_ids = _collect_existing_ids(config)
    next_priority = _initial_priority(config)

    for item in parsed:
        if item.intent == "unknown":
            skipped.append(
                {
                    "requirement": item.raw_text,
                    "reason": "No deterministic parser matched this requirement.",
                }
            )
            continue

        rule = _build_rule(item=item, existing_ids=existing_ids, priority=next_priority)
        if rule is None:
            skipped.append(
                {
                    "requirement": item.raw_text,
                    "reason": "Parsed requirement did not have enough parameters.",
                }
            )
            continue

        existing_ids.add(rule["id"])
        next_priority += 10
        generated_rules.append(rule)
        target_collection.rules.append(rule)

    return generated_rules, skipped


def _build_rule(
    *, item: ParsedRequirement, existing_ids: set[str], priority: int
) -> dict[str, Any] | None:
    params = item.params
    intent = item.intent
    source = item.raw_text

    if intent == "block_path":
        path = params.get("path")
        if not isinstance(path, str):
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="block",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path},
            id_hint=path,
        )

    if intent == "allow_path":
        path = params.get("path")
        if not isinstance(path, str):
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="allow",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path},
            id_hint=path,
        )

    if intent == "rate_limit_path":
        path = params.get("path")
        limit = params.get("limit_per_minute")
        if not isinstance(path, str) or not isinstance(limit, int):
            return None
        rule = _base_rule(
            existing_ids=existing_ids,
            action="rate_limit",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path},
            id_hint=f"{path}-{limit}",
        )
        rule["limit_per_minute"] = limit
        return rule

    if intent == "block_ip":
        cidrs = params.get("ip_cidrs")
        if not isinstance(cidrs, list) or not cidrs:
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="block",
            intent=intent,
            priority=priority,
            source=source,
            match={"ip_cidrs": cidrs},
            id_hint="-".join(cidrs),
        )

    if intent == "allow_ip":
        cidrs = params.get("ip_cidrs")
        if not isinstance(cidrs, list) or not cidrs:
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="allow",
            intent=intent,
            priority=priority,
            source=source,
            match={"ip_cidrs": cidrs},
            id_hint="-".join(cidrs),
        )

    if intent == "block_country":
        countries = params.get("country_codes")
        if not isinstance(countries, list) or not countries:
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="block",
            intent=intent,
            priority=priority,
            source=source,
            match={"country_codes": countries},
            id_hint="-".join(countries),
        )

    if intent == "allow_country":
        countries = params.get("country_codes")
        if not isinstance(countries, list) or not countries:
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="allow",
            intent=intent,
            priority=priority,
            source=source,
            match={"country_codes": countries},
            id_hint="-".join(countries),
        )

    if intent == "allow_methods_path":
        path = params.get("path")
        methods = params.get("methods")
        if not isinstance(path, str) or not isinstance(methods, list) or not methods:
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="allow",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path, "methods": methods},
            id_hint=f"{path}-{'-'.join(methods)}",
        )

    if intent == "require_header_path":
        path = params.get("path")
        header = params.get("header")
        value = params.get("header_value")
        if not isinstance(path, str) or not isinstance(header, str):
            return None
        rule = _base_rule(
            existing_ids=existing_ids,
            action="block",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path},
            id_hint=f"{path}-{header}",
        )
        rule["required_headers"] = {header: value or "required"}
        return rule

    if intent == "challenge_path":
        path = params.get("path")
        if not isinstance(path, str):
            return None
        return _base_rule(
            existing_ids=existing_ids,
            action="challenge",
            intent=intent,
            priority=priority,
            source=source,
            match={"path": path},
            id_hint=path,
        )

    return None


def _base_rule(
    *,
    existing_ids: set[str],
    action: str,
    intent: str,
    priority: int,
    source: str,
    match: dict[str, Any],
    id_hint: str,
) -> dict[str, Any]:
    rule_id = _next_rule_id(existing_ids, f"{action}-{intent}-{_slugify(id_hint)}")
    return {
        "id": rule_id,
        "description": f"Generated from requirement: {source}",
        "action": action,
        "priority": priority,
        "match": match,
        "metadata": {"generated_by": "aem_waf_cdn_agent", "source_requirement": source},
    }


def _collect_existing_ids(config: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for collection in extract_rule_collections(config):
        for rule in collection.rules:
            if not isinstance(rule, dict):
                continue
            for key in ("id", "name", "rule_id"):
                candidate = rule.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    values.add(candidate.strip())
                    break
    return values


def _initial_priority(config: dict[str, Any]) -> int:
    highest = 90
    for collection in extract_rule_collections(config):
        for rule in collection.rules:
            if not isinstance(rule, dict):
                continue
            value = rule.get("priority")
            if isinstance(value, int):
                highest = max(highest, value)
    return highest + 10


def _next_rule_id(existing_ids: set[str], base: str) -> str:
    candidate = base[:96] if len(base) > 96 else base
    if candidate not in existing_ids:
        return candidate
    counter = 2
    while True:
        fallback = f"{candidate}-{counter}"
        if fallback not in existing_ids:
            return fallback
        counter += 1


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return normalized or "rule"

"""Helpers for loading and navigating CDN configuration data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

RULE_HINT_KEYS = {
    "id",
    "name",
    "action",
    "match",
    "when",
    "rateLimit",
    "conditions",
    "path",
    "path_regex",
    "ip_cidrs",
    "country_codes",
    "methods",
}


@dataclass(slots=True)
class RuleCollection:
    """A discovered rules list and its location."""

    path: tuple[Any, ...]
    rules: list[dict[str, Any]]

    @property
    def path_string(self) -> str:
        if not self.path:
            return "$"
        return "$." + ".".join(str(part) for part in self.path)


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load YAML as dictionary while preserving insertion order."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("cdn.yaml must contain a mapping at the top level.")
    return data


def dump_yaml(path: str | Path, data: dict[str, Any]) -> None:
    """Write YAML in a stable and human-friendly format."""
    with Path(path).open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )


def extract_rule_collections(config: dict[str, Any]) -> list[RuleCollection]:
    """Find candidate rule collections in common and nested schemas."""
    collections: list[RuleCollection] = []
    seen_paths: set[tuple[Any, ...]] = set()

    def append_collection(path: tuple[Any, ...], rules: list[Any]) -> None:
        if path in seen_paths:
            return
        if not all(isinstance(item, dict) for item in rules):
            return
        seen_paths.add(path)
        collections.append(RuleCollection(path=path, rules=rules))

    prioritized_paths: list[tuple[str, ...]] = [
        ("data", "trafficFilters", "rules"),
        ("rules",),
        ("waf", "rules"),
        ("cdn", "rules"),
        ("data", "rules"),
        ("spec", "rules"),
        ("security", "rules"),
    ]
    for candidate in prioritized_paths:
        node: Any = config
        valid = True
        for part in candidate:
            if not isinstance(node, dict) or part not in node:
                valid = False
                break
            node = node[part]
        if valid and isinstance(node, list):
            append_collection(candidate, node)

    def walk(node: Any, path: tuple[Any, ...]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, (*path, key))
            return
        if isinstance(node, list):
            if not node:
                return
            parent_key = path[-1] if path else ""
            if isinstance(parent_key, str) and "rule" in parent_key.lower():
                append_collection(path, node)
            elif all(isinstance(item, dict) for item in node):
                if any(RULE_HINT_KEYS.intersection(item.keys()) for item in node):
                    append_collection(path, node)
            for index, item in enumerate(node):
                walk(item, (*path, index))

    walk(config, ())
    return collections


def ensure_primary_rule_collection(config: dict[str, Any]) -> RuleCollection:
    """Return best target rule list, creating one if missing."""
    collections = extract_rule_collections(config)
    if collections:
        for collection in collections:
            if collection.path == ("data", "trafficFilters", "rules"):
                return collection
        return collections[0]
    data = config.get("data")
    if not isinstance(data, dict):
        data = {}
        config["data"] = data
    traffic_filters = data.get("trafficFilters")
    if not isinstance(traffic_filters, dict):
        traffic_filters = {}
        data["trafficFilters"] = traffic_filters
    traffic_filters["rules"] = []
    return RuleCollection(path=("data", "trafficFilters", "rules"), rules=traffic_filters["rules"])

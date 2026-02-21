"""Feature pack templates for MCP-driven rule insertion."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

FEATURE_PACK_DESCRIPTIONS: dict[str, str] = {
    "standard_recommended": (
        "Adobe-style standard starter rules: edge/origin rate-limit monitoring "
        "and OFAC country blocking."
    ),
    "waf_recommended": (
        "Adobe-style WAF starter rules using ATTACK-FROM-BAD-IP and ATTACK flags."
    ),
    "auth_monitoring": (
        "Log monitoring rules for AEM authentication endpoints on publish tier."
    ),
}


def build_feature_pack(feature_name: str, *, mode: str = "safe") -> list[dict[str, Any]]:
    """Build a named feature pack as list of rules."""
    normalized = feature_name.strip().lower()
    normalized_mode = mode.strip().lower()

    if normalized == "standard_recommended":
        return deepcopy(_standard_recommended_rules())
    if normalized == "waf_recommended":
        return deepcopy(_waf_recommended_rules(mode=normalized_mode))
    if normalized == "auth_monitoring":
        return deepcopy(_auth_monitoring_rules())
    raise ValueError(
        f"Unknown feature_name '{feature_name}'. Supported values: "
        f"{', '.join(sorted(FEATURE_PACK_DESCRIPTIONS))}"
    )


def _standard_recommended_rules() -> list[dict[str, Any]]:
    return [
        {
            "name": "prevent-dos-attacks-edge",
            "when": {"reqProperty": "tier", "equals": "publish"},
            "rateLimit": {
                "limit": 500,
                "window": 10,
                "penalty": 300,
                "count": "all",
                "groupBy": [{"reqProperty": "clientIp"}],
            },
            "action": {"type": "log", "alert": True},
        },
        {
            "name": "prevent-dos-attacks-origin",
            "when": {"reqProperty": "tier", "equals": "publish"},
            "rateLimit": {
                "limit": 100,
                "window": 10,
                "penalty": 300,
                "count": "fetches",
                "groupBy": [{"reqProperty": "clientIp"}],
            },
            "action": {"type": "log", "alert": True},
        },
        {
            "name": "block-ofac-countries",
            "when": {
                "allOf": [
                    {"reqProperty": "tier", "in": ["author", "publish"]},
                    {
                        "reqProperty": "clientCountry",
                        "in": [
                            "SY",
                            "BY",
                            "MM",
                            "KP",
                            "IQ",
                            "CD",
                            "SD",
                            "IR",
                            "LR",
                            "ZW",
                            "CU",
                            "CI",
                        ],
                    },
                ]
            },
            "action": "block",
        },
    ]


def _waf_recommended_rules(*, mode: str) -> list[dict[str, Any]]:
    if mode not in {"safe", "strict"}:
        raise ValueError("mode for waf_recommended must be one of: safe, strict")

    attack_rule_action = {"type": "log", "alert": True}
    if mode == "strict":
        attack_rule_action = {"type": "block", "alert": True}

    return [
        {
            "name": "attacks-from-bad-ips-globally",
            "when": {"reqProperty": "tier", "in": ["author", "publish"]},
            "action": {"type": "block", "wafFlags": ["ATTACK-FROM-BAD-IP"]},
        },
        {
            "name": "attacks-from-any-ips-globally",
            "when": {"reqProperty": "tier", "in": ["author", "publish"]},
            "action": {**attack_rule_action, "wafFlags": ["ATTACK"]},
        },
    ]


def _auth_monitoring_rules() -> list[dict[str, Any]]:
    return [
        {
            "name": "publish-auth-requests",
            "when": {
                "allOf": [
                    {"reqProperty": "tier", "matches": "publish"},
                    {
                        "reqProperty": "path",
                        "in": [
                            "/system/sling/login/j_security_check",
                            "/system/sling/logout",
                        ],
                    },
                ]
            },
            "action": {"type": "log"},
        }
    ]

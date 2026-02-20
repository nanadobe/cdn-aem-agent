"""AEM-focused WAF/CDN configuration analyzer based on Adobe documentation."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .config import RuleCollection, extract_rule_collections
from .models import AnalysisReport

DOC_REFERENCES = (
    "https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf",
    "https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic",
    "https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf?lang=en",
)

ALLOWED_ACTION_TYPES = {"allow", "block", "log"}
ALLOWED_GETTERS = {"reqProperty", "reqHeader", "queryParam", "reqCookie", "postParam"}
ALLOWED_PREDICATES = {
    "equals",
    "doesNotEqual",
    "like",
    "notLike",
    "matches",
    "doesNotMatch",
    "in",
    "notIn",
    "exists",
}
ALLOWED_CLIENT_IP_PREDICATES = {"equals", "doesNotEqual", "in", "notIn"}
ALLOWED_REQ_PROPERTIES = {
    "path",
    "pathRaw",
    "url",
    "urlRaw",
    "queryString",
    "method",
    "tier",
    "domain",
    "clientIp",
    "forwardedDomain",
    "forwardedIp",
    "clientRegion",
    "clientCountry",
    "clientContinent",
    "clientAsNumber",
    "clientAsName",
}
ALLOWED_TIER_VALUES = {"author", "preview", "publish"}
ALLOWED_RATE_LIMIT_COUNTS = {"all", "fetches", "errors"}
ALLOWED_WAF_FLAGS = {
    # Malicious traffic
    "ATTACK",
    "ATTACK-FROM-BAD-IP",
    "SQLI",
    "BACKDOOR",
    "CMDEXE",
    "CMDEXE-NO-BIN",
    "XSS",
    "TRAVERSAL",
    "USERAGENT",
    "LOG4J-JNDI",
    "CVE",
    # Suspicious traffic
    "ABNORMALPATH",
    "BAD-IP",
    "BHH",
    "CODEINJECTION",
    "COMPRESSED",
    "RESPONSESPLIT",
    "NOTUTF8",
    "UTF8",  # legacy in some tutorials
    "MALFORMED-DATA",
    "SANS",
    "NO-CONTENT-TYPE",
    "NOUA",
    "NULLBYTE",
    "OOB-DOMAIN",
    "PRIVATEFILE",
    "SCANNER",
    # Misc
    "DATACENTER",
    "DOUBLEENCODING",
    "JSON-ERROR",
    "TORNODE",
    "XML-ERROR",
}
OFAC_COUNTRY_CODES = {"SY", "BY", "MM", "KP", "IQ", "CD", "SD", "IR", "LR", "ZW", "CU", "CI"}


def analyze_config(config: dict[str, Any]) -> AnalysisReport:
    """Run syntax and AEM-focused checks against CDN config."""
    report = AnalysisReport()
    _validate_top_level(config, report)

    collections = extract_rule_collections(config)
    report.collection_count = len(collections)
    report.rule_count = sum(len(collection.rules) for collection in collections)

    if not collections:
        report.add(
            code="MISSING_RULE_COLLECTION",
            severity="error",
            message="No rule collections were found. Expected data.trafficFilters.rules.",
            recommendation=(
                "Declare traffic filter rules under data.trafficFilters.rules as described "
                f"in Adobe docs: {DOC_REFERENCES[0]}"
            ),
        )
        return report

    seen_names: dict[str, str] = {}
    recommendation_flags = {
        "edge_rate_limit": False,
        "origin_rate_limit": False,
        "ofac_block": False,
        "attack_from_bad_ip": False,
        "attack_any_ip": False,
    }

    for collection in collections:
        _analyze_collection(
            collection=collection,
            report=report,
            seen_names=seen_names,
            recommendation_flags=recommendation_flags,
        )

    _check_recommended_baseline(report, recommendation_flags)
    return report


def _validate_top_level(config: dict[str, Any], report: AnalysisReport) -> None:
    kind = config.get("kind")
    version = config.get("version")
    if isinstance(kind, str):
        if kind.strip('"').strip("'").upper() != "CDN":
            report.add(
                code="UNEXPECTED_KIND",
                severity="warning",
                message=f"Top-level kind '{kind}' is not CDN.",
                recommendation="Use kind: \"CDN\".",
            )
    else:
        report.add(
            code="MISSING_KIND",
            severity="warning",
            message="Missing top-level kind field.",
            recommendation="Set kind: \"CDN\".",
        )

    if isinstance(version, str):
        normalized = version.strip('"').strip("'")
        if normalized != "1":
            report.add(
                code="UNEXPECTED_VERSION",
                severity="warning",
                message=f"Top-level version '{version}' is not '1'.",
                recommendation="Use version: \"1\".",
            )
    elif isinstance(version, int):
        if version != 1:
            report.add(
                code="UNEXPECTED_VERSION",
                severity="warning",
                message=f"Top-level version '{version}' is not 1.",
                recommendation="Use version: \"1\".",
            )
    else:
        report.add(
            code="MISSING_VERSION",
            severity="warning",
            message="Missing top-level version field.",
            recommendation="Set version: \"1\".",
        )


def _analyze_collection(
    *,
    collection: RuleCollection,
    report: AnalysisReport,
    seen_names: dict[str, str],
    recommendation_flags: dict[str, bool],
) -> None:
    for index, rule in enumerate(collection.rules):
        rule_path = f"{collection.path_string}[{index}]"
        if not isinstance(rule, dict):
            report.add(
                code="INVALID_RULE_OBJECT",
                severity="error",
                message="Rule entry is not a mapping/object.",
                path=rule_path,
            )
            continue

        rule_name = _extract_rule_name(rule, index=index)
        _validate_rule_name(report=report, rule=rule, rule_path=rule_path, rule_name=rule_name)

        if rule_name in seen_names:
            report.add(
                code="DUPLICATE_RULE_NAME",
                severity="error",
                message=f"Rule name '{rule_name}' duplicates {seen_names[rule_name]}.",
                path=rule_path,
                rule_id=rule_name,
            )
        else:
            seen_names[rule_name] = rule_path

        when = rule.get("when")
        if when is None:
            report.add(
                code="MISSING_WHEN_CONDITION",
                severity="error",
                message="Rule is missing required 'when' condition.",
                path=rule_path,
                rule_id=rule_name,
            )
            condition_summary = {}
        else:
            condition_summary = _validate_condition(
                when=when,
                report=report,
                rule_path=f"{rule_path}.when",
                rule_name=rule_name,
            )

        action_info = _validate_action(
            action=rule.get("action"),
            rule_alert=rule.get("alert"),
            report=report,
            rule_path=f"{rule_path}.action",
            rule_name=rule_name,
        )
        rate_limit = rule.get("rateLimit")
        rate_limit_info = _validate_rate_limit(
            rate_limit=rate_limit,
            report=report,
            rule_path=f"{rule_path}.rateLimit",
            rule_name=rule_name,
        )

        if rate_limit is not None and action_info["waf_flags"]:
            report.add(
                code="INVALID_RATE_LIMIT_WITH_WAF_FLAGS",
                severity="error",
                message=(
                    "rateLimit cannot be combined with wafFlags in the same rule "
                    "(per Adobe docs)."
                ),
                path=rule_path,
                rule_id=rule_name,
            )

        _collect_recommendation_flags(
            recommendation_flags=recommendation_flags,
            action_info=action_info,
            condition_summary=condition_summary,
            rate_limit_info=rate_limit_info,
        )

    if not collection.path[:3] == ("data", "trafficFilters", "rules"):
        report.add(
            code="NON_STANDARD_RULE_COLLECTION",
            severity="warning",
            message=(
                f"Rules found at {collection.path_string}. Adobe docs typically place "
                "traffic filter rules at $.data.trafficFilters.rules."
            ),
            recommendation=f"Prefer the canonical syntax described at {DOC_REFERENCES[0]}",
        )


def _validate_rule_name(
    *, report: AnalysisReport, rule: dict[str, Any], rule_path: str, rule_name: str
) -> None:
    name = rule.get("name")
    if not isinstance(name, str) or not name.strip():
        report.add(
            code="MISSING_RULE_NAME",
            severity="error",
            message="Rule is missing required 'name' field.",
            path=rule_path,
            rule_id=rule_name,
        )
        return
    if len(name) > 64:
        report.add(
            code="RULE_NAME_TOO_LONG",
            severity="error",
            message="Rule name must be at most 64 characters (Adobe syntax).",
            path=rule_path,
            rule_id=rule_name,
        )
    if not re.fullmatch(r"[A-Za-z0-9-]+", name):
        report.add(
            code="INVALID_RULE_NAME_FORMAT",
            severity="error",
            message="Rule name can only contain alphanumerics and '-'.",
            path=rule_path,
            rule_id=rule_name,
        )


def _validate_condition(
    *,
    when: Any,
    report: AnalysisReport,
    rule_path: str,
    rule_name: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "req_properties": set(),
        "client_country_values": set(),
        "tier_values": set(),
    }
    if when == "*":
        return summary
    if not isinstance(when, dict):
        report.add(
            code="INVALID_WHEN_CONDITION",
            severity="error",
            message="'when' must be a condition map/object.",
            path=rule_path,
            rule_id=rule_name,
        )
        return summary
    _validate_condition_node(
        node=when,
        report=report,
        path=rule_path,
        rule_name=rule_name,
        summary=summary,
    )
    return summary


def _validate_condition_node(
    *,
    node: Any,
    report: AnalysisReport,
    path: str,
    rule_name: str,
    summary: dict[str, Any],
) -> None:
    if not isinstance(node, dict):
        report.add(
            code="INVALID_CONDITION_NODE",
            severity="error",
            message="Condition node must be an object.",
            path=path,
            rule_id=rule_name,
        )
        return

    if "allOf" in node or "anyOf" in node:
        for group_key in ("allOf", "anyOf"):
            if group_key not in node:
                continue
            group_value = node[group_key]
            if not isinstance(group_value, list) or not group_value:
                report.add(
                    code="INVALID_CONDITION_GROUP",
                    severity="error",
                    message=f"'{group_key}' must be a non-empty list of conditions.",
                    path=path,
                    rule_id=rule_name,
                )
                continue
            for idx, child in enumerate(group_value):
                _validate_condition_node(
                    node=child,
                    report=report,
                    path=f"{path}.{group_key}[{idx}]",
                    rule_name=rule_name,
                    summary=summary,
                )
        return

    getter_keys = [key for key in ALLOWED_GETTERS if key in node]
    predicate_keys = [key for key in ALLOWED_PREDICATES if key in node]

    if len(getter_keys) != 1:
        report.add(
            code="INVALID_CONDITION_GETTER",
            severity="error",
            message="Condition must contain exactly one getter key.",
            path=path,
            rule_id=rule_name,
        )
        return
    if len(predicate_keys) != 1:
        report.add(
            code="INVALID_CONDITION_PREDICATE",
            severity="error",
            message="Condition must contain exactly one predicate key.",
            path=path,
            rule_id=rule_name,
        )
        return

    getter_key = getter_keys[0]
    getter_value = node[getter_key]
    predicate_key = predicate_keys[0]
    predicate_value = node[predicate_key]

    if not isinstance(getter_value, str) or not getter_value.strip():
        report.add(
            code="INVALID_GETTER_VALUE",
            severity="error",
            message=f"Getter '{getter_key}' must have a non-empty string value.",
            path=path,
            rule_id=rule_name,
        )
        return

    if getter_key == "reqProperty":
        req_property = getter_value.strip()
        summary["req_properties"].add(req_property)
        if req_property not in ALLOWED_REQ_PROPERTIES:
            report.add(
                code="UNSUPPORTED_REQ_PROPERTY",
                severity="error",
                message=f"Unsupported reqProperty '{req_property}'.",
                path=path,
                rule_id=rule_name,
            )
        if req_property == "clientIp" and predicate_key not in ALLOWED_CLIENT_IP_PREDICATES:
            report.add(
                code="INVALID_CLIENT_IP_PREDICATE",
                severity="error",
                message=(
                    "clientIp can only be used with equals, doesNotEqual, in, or notIn."
                ),
                path=path,
                rule_id=rule_name,
            )

    _validate_predicate_value(
        report=report,
        path=path,
        rule_name=rule_name,
        predicate_key=predicate_key,
        predicate_value=predicate_value,
        req_property=getter_value if getter_key == "reqProperty" else None,
        summary=summary,
    )


def _validate_predicate_value(
    *,
    report: AnalysisReport,
    path: str,
    rule_name: str,
    predicate_key: str,
    predicate_value: Any,
    req_property: str | None,
    summary: dict[str, Any],
) -> None:
    if predicate_key == "exists":
        if not isinstance(predicate_value, bool):
            report.add(
                code="INVALID_EXISTS_PREDICATE",
                severity="error",
                message="'exists' predicate requires a boolean value.",
                path=path,
                rule_id=rule_name,
            )
        return

    if predicate_key in {"in", "notIn"}:
        if not isinstance(predicate_value, list) or not predicate_value:
            report.add(
                code="INVALID_LIST_PREDICATE",
                severity="error",
                message=f"'{predicate_key}' predicate requires a non-empty list.",
                path=path,
                rule_id=rule_name,
            )
            return
        for idx, item in enumerate(predicate_value):
            if not isinstance(item, str):
                report.add(
                    code="INVALID_LIST_PREDICATE_ITEM",
                    severity="error",
                    message=f"'{predicate_key}' list items must be strings.",
                    path=f"{path}.{predicate_key}[{idx}]",
                    rule_id=rule_name,
                )
                continue
            _validate_property_specific_value(
                report=report,
                path=f"{path}.{predicate_key}[{idx}]",
                rule_name=rule_name,
                req_property=req_property,
                value=item,
                summary=summary,
            )
        return

    if not isinstance(predicate_value, str):
        report.add(
            code="INVALID_PREDICATE_VALUE",
            severity="error",
            message=f"'{predicate_key}' predicate expects a string value.",
            path=path,
            rule_id=rule_name,
        )
        return

    if predicate_key in {"matches", "doesNotMatch"}:
        try:
            re.compile(predicate_value)
        except re.error as exc:
            report.add(
                code="INVALID_REGEX_PREDICATE",
                severity="error",
                message=f"Invalid regex in '{predicate_key}': {exc}",
                path=path,
                rule_id=rule_name,
            )

    _validate_property_specific_value(
        report=report,
        path=f"{path}.{predicate_key}",
        rule_name=rule_name,
        req_property=req_property,
        value=predicate_value,
        summary=summary,
    )


def _validate_property_specific_value(
    *,
    report: AnalysisReport,
    path: str,
    rule_name: str,
    req_property: str | None,
    value: str,
    summary: dict[str, Any],
) -> None:
    if req_property == "clientIp":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            report.add(
                code="INVALID_CLIENT_IP_VALUE",
                severity="error",
                message=f"Invalid clientIp matcher '{value}'.",
                path=path,
                rule_id=rule_name,
            )
    elif req_property == "clientCountry":
        country = value.upper()
        summary["client_country_values"].add(country)
        if not re.fullmatch(r"[A-Z]{2}", country):
            report.add(
                code="INVALID_COUNTRY_CODE",
                severity="warning",
                message="clientCountry values should be ISO-3166 alpha-2 codes.",
                path=path,
                rule_id=rule_name,
            )
    elif req_property == "tier":
        tier = value.lower()
        summary["tier_values"].add(tier)
        if tier not in ALLOWED_TIER_VALUES:
            report.add(
                code="INVALID_TIER_VALUE",
                severity="error",
                message="tier must be one of author, preview, publish.",
                path=path,
                rule_id=rule_name,
            )


def _validate_action(
    *,
    action: Any,
    rule_alert: Any,
    report: AnalysisReport,
    rule_path: str,
    rule_name: str,
) -> dict[str, Any]:
    info = {"type": "log", "waf_flags": []}
    if rule_alert is not None and not isinstance(rule_alert, bool):
        report.add(
            code="INVALID_RULE_ALERT",
            severity="error",
            message="Rule-level alert must be a boolean when provided.",
            path=rule_path.replace(".action", ".alert"),
            rule_id=rule_name,
        )
    if action is None:
        report.add(
            code="MISSING_ACTION_DEFAULT_LOG",
            severity="info",
            message="Rule action is omitted; Adobe syntax defaults this to log.",
            path=rule_path,
            rule_id=rule_name,
        )
        return info

    action_type: str | None = None
    waf_flags: list[str] = []

    if isinstance(action, str):
        action_type = action.strip().lower()
    elif isinstance(action, dict):
        raw_type = action.get("type")
        if not isinstance(raw_type, str):
            report.add(
                code="MISSING_ACTION_TYPE",
                severity="error",
                message="Action object must include a string 'type'.",
                path=rule_path,
                rule_id=rule_name,
            )
            raw_type = ""
        action_type = raw_type.strip().lower()

        alert = action.get("alert")
        if alert is not None and not isinstance(alert, bool):
            report.add(
                code="INVALID_ACTION_ALERT",
                severity="error",
                message="Action 'alert' must be a boolean.",
                path=rule_path,
                rule_id=rule_name,
            )
        if rule_alert is not None and alert is not None:
            report.add(
                code="DUPLICATE_ALERT_DECLARATION",
                severity="warning",
                message="Both rule-level alert and action.alert are set; prefer one location.",
                path=rule_path,
                rule_id=rule_name,
            )

        waf_value = action.get("wafFlags")
        if waf_value is not None:
            if not isinstance(waf_value, list) or not waf_value:
                report.add(
                    code="INVALID_WAF_FLAGS",
                    severity="error",
                    message="wafFlags must be a non-empty list of flag IDs.",
                    path=rule_path,
                    rule_id=rule_name,
                )
            else:
                for idx, flag in enumerate(waf_value):
                    if not isinstance(flag, str):
                        report.add(
                            code="INVALID_WAF_FLAG_ITEM",
                            severity="error",
                            message="Each wafFlags item must be a string.",
                            path=f"{rule_path}.wafFlags[{idx}]",
                            rule_id=rule_name,
                        )
                        continue
                    normalized = flag.strip().upper()
                    waf_flags.append(normalized)
                    if normalized not in ALLOWED_WAF_FLAGS and not normalized.startswith("CVE-"):
                        report.add(
                            code="UNKNOWN_WAF_FLAG",
                            severity="warning",
                            message=f"Unknown wafFlag '{flag}'.",
                            path=f"{rule_path}.wafFlags[{idx}]",
                            rule_id=rule_name,
                        )

        status = action.get("status")
        if status is not None:
            if not isinstance(status, int) or not (100 <= status <= 599):
                report.add(
                    code="INVALID_BLOCK_STATUS",
                    severity="error",
                    message="Action status must be an integer HTTP code (100-599).",
                    path=rule_path,
                    rule_id=rule_name,
                )
    else:
        report.add(
            code="INVALID_ACTION_FORMAT",
            severity="error",
            message="Action must be either a string or an object.",
            path=rule_path,
            rule_id=rule_name,
        )
        return info

    if action_type not in ALLOWED_ACTION_TYPES:
        report.add(
            code="UNSUPPORTED_ACTION_TYPE",
            severity="error",
            message=f"Unsupported action type '{action_type}'.",
            path=rule_path,
            rule_id=rule_name,
        )
        return info

    if isinstance(action, dict):
        has_status = "status" in action
        has_waf_flags = bool(waf_flags)
        if action_type != "block" and has_status:
            report.add(
                code="STATUS_ONLY_VALID_FOR_BLOCK",
                severity="error",
                message="status is only valid when action type is block.",
                path=rule_path,
                rule_id=rule_name,
            )
        if action_type == "block" and has_status and has_waf_flags:
            report.add(
                code="STATUS_AND_WAF_FLAGS_MUTUALLY_EXCLUSIVE",
                severity="error",
                message="block action cannot define both status and wafFlags.",
                path=rule_path,
                rule_id=rule_name,
            )

    info["type"] = action_type
    info["waf_flags"] = waf_flags
    return info


def _validate_rate_limit(
    *,
    rate_limit: Any,
    report: AnalysisReport,
    rule_path: str,
    rule_name: str,
) -> dict[str, Any]:
    info = {"enabled": False, "limit": None, "count": None, "group_by_client_ip": False}
    if rate_limit is None:
        return info
    if not isinstance(rate_limit, dict):
        report.add(
            code="INVALID_RATE_LIMIT_OBJECT",
            severity="error",
            message="rateLimit must be an object.",
            path=rule_path,
            rule_id=rule_name,
        )
        return info

    info["enabled"] = True
    limit = rate_limit.get("limit")
    if not isinstance(limit, int):
        report.add(
            code="RATE_LIMIT_LIMIT_REQUIRED",
            severity="error",
            message="rateLimit.limit is required and must be an integer.",
            path=f"{rule_path}.limit",
            rule_id=rule_name,
        )
    elif not (10 <= limit <= 10000):
        report.add(
            code="RATE_LIMIT_LIMIT_RANGE",
            severity="error",
            message="rateLimit.limit must be between 10 and 10000.",
            path=f"{rule_path}.limit",
            rule_id=rule_name,
        )
    else:
        info["limit"] = limit

    window = rate_limit.get("window", 10)
    if not isinstance(window, int) or window not in {1, 10, 60}:
        report.add(
            code="INVALID_RATE_LIMIT_WINDOW",
            severity="error",
            message="rateLimit.window must be one of 1, 10, or 60.",
            path=f"{rule_path}.window",
            rule_id=rule_name,
        )

    penalty = rate_limit.get("penalty", 300)
    if not isinstance(penalty, int) or not (60 <= penalty <= 3600):
        report.add(
            code="INVALID_RATE_LIMIT_PENALTY",
            severity="error",
            message="rateLimit.penalty must be between 60 and 3600.",
            path=f"{rule_path}.penalty",
            rule_id=rule_name,
        )

    count = rate_limit.get("count", "all")
    if not isinstance(count, str) or count not in ALLOWED_RATE_LIMIT_COUNTS:
        report.add(
            code="INVALID_RATE_LIMIT_COUNT",
            severity="error",
            message="rateLimit.count must be one of all, fetches, errors.",
            path=f"{rule_path}.count",
            rule_id=rule_name,
        )
    else:
        info["count"] = count

    group_by = rate_limit.get("groupBy", [])
    if group_by is not None:
        if not isinstance(group_by, list):
            report.add(
                code="INVALID_RATE_LIMIT_GROUPBY",
                severity="error",
                message="rateLimit.groupBy must be a list of getter maps.",
                path=f"{rule_path}.groupBy",
                rule_id=rule_name,
            )
        else:
            for idx, getter in enumerate(group_by):
                if not isinstance(getter, dict):
                    report.add(
                        code="INVALID_RATE_LIMIT_GROUPBY_ENTRY",
                        severity="error",
                        message="Each groupBy entry must be an object getter.",
                        path=f"{rule_path}.groupBy[{idx}]",
                        rule_id=rule_name,
                    )
                    continue
                _validate_getter_map(
                    getter=getter,
                    report=report,
                    path=f"{rule_path}.groupBy[{idx}]",
                    rule_name=rule_name,
                )
                if getter.get("reqProperty") == "clientIp":
                    info["group_by_client_ip"] = True
    return info


def _validate_getter_map(
    *,
    getter: dict[str, Any],
    report: AnalysisReport,
    path: str,
    rule_name: str,
) -> None:
    getter_keys = [key for key in ALLOWED_GETTERS if key in getter]
    if len(getter_keys) != 1:
        report.add(
            code="INVALID_GETTER_MAP",
            severity="error",
            message="Getter map must include exactly one getter field.",
            path=path,
            rule_id=rule_name,
        )
        return
    key = getter_keys[0]
    value = getter[key]
    if not isinstance(value, str) or not value.strip():
        report.add(
            code="INVALID_GETTER_MAP_VALUE",
            severity="error",
            message=f"Getter '{key}' must have a non-empty string value.",
            path=path,
            rule_id=rule_name,
        )
        return
    if key == "reqProperty" and value not in ALLOWED_REQ_PROPERTIES:
        report.add(
            code="UNSUPPORTED_REQ_PROPERTY",
            severity="error",
            message=f"Unsupported reqProperty '{value}'.",
            path=path,
            rule_id=rule_name,
        )


def _collect_recommendation_flags(
    *,
    recommendation_flags: dict[str, bool],
    action_info: dict[str, Any],
    condition_summary: dict[str, Any],
    rate_limit_info: dict[str, Any],
) -> None:
    action_type = action_info["type"]
    waf_flags = set(action_info["waf_flags"])
    tiers = {value.lower() for value in condition_summary.get("tier_values", set())}
    country_values = {value.upper() for value in condition_summary.get("client_country_values", set())}

    applies_publish = not tiers or "publish" in tiers

    if rate_limit_info["enabled"] and applies_publish:
        limit = rate_limit_info["limit"]
        count = rate_limit_info["count"]
        group_by_ip = rate_limit_info["group_by_client_ip"]
        if group_by_ip and count == "all" and isinstance(limit, int) and limit >= 500:
            recommendation_flags["edge_rate_limit"] = True
        if group_by_ip and count == "fetches" and isinstance(limit, int) and limit >= 100:
            recommendation_flags["origin_rate_limit"] = True

    if action_type == "block" and country_values and OFAC_COUNTRY_CODES.issubset(country_values):
        recommendation_flags["ofac_block"] = True

    if "ATTACK-FROM-BAD-IP" in waf_flags and action_type == "block":
        recommendation_flags["attack_from_bad_ip"] = True
    if "ATTACK" in waf_flags and action_type in {"log", "block"}:
        recommendation_flags["attack_any_ip"] = True


def _check_recommended_baseline(
    report: AnalysisReport, recommendation_flags: dict[str, bool]
) -> None:
    if not recommendation_flags["edge_rate_limit"]:
        report.add(
            code="MISSING_RECOMMENDED_EDGE_RATE_LIMIT",
            severity="warning",
            message=(
                "Recommended baseline edge DoS rule not detected "
                "(publish tier, count=all, groupBy clientIp, limit around 500)."
            ),
            recommendation=(
                "See Adobe recommended standard starter rules in "
                "Traffic Filter Rules docs."
            ),
        )
    if not recommendation_flags["origin_rate_limit"]:
        report.add(
            code="MISSING_RECOMMENDED_ORIGIN_RATE_LIMIT",
            severity="warning",
            message=(
                "Recommended baseline origin DoS rule not detected "
                "(publish tier, count=fetches, groupBy clientIp, limit around 100)."
            ),
            recommendation="Add the recommended origin rate-limit starter rule from Adobe docs.",
        )
    if not recommendation_flags["ofac_block"]:
        report.add(
            code="MISSING_RECOMMENDED_OFAC_BLOCK_RULE",
            severity="info",
            message="No OFAC-style country block rule was detected.",
            recommendation="Consider Adobe's optional OFAC starter rule if it matches policy.",
        )
    if not recommendation_flags["attack_from_bad_ip"]:
        report.add(
            code="MISSING_RECOMMENDED_ATTACK_FROM_BAD_IP_RULE",
            severity="info",
            message="No ATTACK-FROM-BAD-IP block rule detected.",
            recommendation=(
                "If WAF is licensed, add Adobe's recommended ATTACK-FROM-BAD-IP block rule."
            ),
        )
    if not recommendation_flags["attack_any_ip"]:
        report.add(
            code="MISSING_RECOMMENDED_ATTACK_RULE",
            severity="info",
            message="No ATTACK log/block rule detected.",
            recommendation=(
                "If WAF is licensed, start with ATTACK in log mode, then move to block."
            ),
        )


def _extract_rule_name(rule: dict[str, Any], *, index: int) -> str:
    value = rule.get("name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return f"unnamed-rule-{index + 1}"

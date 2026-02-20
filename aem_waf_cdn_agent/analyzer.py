"""AEM-focused WAF/CDN configuration analyzer."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .config import RuleCollection, extract_rule_collections
from .models import AnalysisReport

ALLOWED_ACTIONS = {"allow", "block", "rate_limit", "challenge", "log"}
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

MANDATORY_SENSITIVE_ENDPOINTS = (
    "/system/console",
    "/crx",
    "/etc/packages",
    "/bin/querybuilder",
)
LOGIN_ENDPOINTS = (
    "/libs/granite/core/content/login",
    "/j_security_check",
    "/system/sling/login",
)


def analyze_config(config: dict[str, Any]) -> AnalysisReport:
    """Run schema and AEM-specific checks on CDN config."""
    report = AnalysisReport()
    collections = extract_rule_collections(config)
    report.collection_count = len(collections)
    report.rule_count = sum(len(collection.rules) for collection in collections)

    if not collections:
        report.add(
            code="MISSING_RULE_COLLECTION",
            severity="error",
            message="No rule collections were found in cdn.yaml.",
            recommendation="Add a top-level 'rules' list or a known rule collection path.",
        )
        return report

    seen_ids: dict[str, str] = {}
    seen_priorities: dict[int, str] = {}
    path_to_actions: dict[str, set[str]] = {}
    protected_sensitive_endpoints: set[str] = set()
    login_rate_limit_present_ref = [False]

    for collection in collections:
        _analyze_collection(
            collection=collection,
            report=report,
            seen_ids=seen_ids,
            seen_priorities=seen_priorities,
            path_to_actions=path_to_actions,
            protected_sensitive_endpoints=protected_sensitive_endpoints,
            login_rate_limit_present_ref=login_rate_limit_present_ref,
        )

    for path_signature, actions in path_to_actions.items():
        if "allow" in actions and "block" in actions:
            report.add(
                code="CONFLICTING_RULE_ACTIONS",
                severity="warning",
                message=(
                    f"Rules targeting '{path_signature}' include both "
                    "'allow' and 'block' actions."
                ),
                recommendation=(
                    "Review priority ordering and consolidate intent to avoid bypasses."
                ),
            )

    for endpoint in MANDATORY_SENSITIVE_ENDPOINTS:
        if endpoint not in protected_sensitive_endpoints:
            report.add(
                code="MISSING_AEM_SENSITIVE_ENDPOINT_GUARD",
                severity="warning",
                message=(
                    f"No blocking/challenge rule appears to protect sensitive AEM "
                    f"endpoint '{endpoint}'."
                ),
                recommendation=(
                    "Add a block or challenge rule for this endpoint, scoped to "
                    "public traffic."
                ),
            )

    if not login_rate_limit_present_ref[0]:
        report.add(
            code="MISSING_LOGIN_RATE_LIMIT",
            severity="warning",
            message="No rate-limit rule found for known AEM authentication endpoints.",
            recommendation=(
                "Add rate_limit controls for '/libs/granite/core/content/login' and "
                "'/j_security_check'."
            ),
        )

    return report


def _analyze_collection(
    *,
    collection: RuleCollection,
    report: AnalysisReport,
    seen_ids: dict[str, str],
    seen_priorities: dict[int, str],
    path_to_actions: dict[str, set[str]],
    protected_sensitive_endpoints: set[str],
    login_rate_limit_present_ref: list[bool],
) -> None:
    for index, rule in enumerate(collection.rules):
        rule_path = f"{collection.path_string}[{index}]"
        if not isinstance(rule, dict):
            report.add(
                code="INVALID_RULE_OBJECT",
                severity="error",
                message="Rule entry is not an object/map.",
                path=rule_path,
                recommendation="Each rule must be a YAML mapping.",
            )
            continue

        rule_id = _coerce_rule_id(rule, index=index)

        action_raw = rule.get("action")
        action = action_raw.lower().strip() if isinstance(action_raw, str) else ""
        if not action:
            report.add(
                code="MISSING_RULE_ACTION",
                severity="error",
                message="Rule does not define an action.",
                path=rule_path,
                rule_id=rule_id,
                recommendation="Set action to one of: allow, block, rate_limit, challenge, log.",
            )
        elif action not in ALLOWED_ACTIONS:
            report.add(
                code="UNSUPPORTED_RULE_ACTION",
                severity="error",
                message=f"Unsupported rule action '{action_raw}'.",
                path=rule_path,
                rule_id=rule_id,
                recommendation=f"Use one of: {', '.join(sorted(ALLOWED_ACTIONS))}.",
            )

        if rule_id in seen_ids:
            report.add(
                code="DUPLICATE_RULE_ID",
                severity="error",
                message=f"Rule id '{rule_id}' duplicates {seen_ids[rule_id]}.",
                path=rule_path,
                rule_id=rule_id,
                recommendation="Use unique stable IDs for each rule.",
            )
        else:
            seen_ids[rule_id] = rule_path

        priority = rule.get("priority")
        if priority is not None:
            if not isinstance(priority, int) or priority <= 0:
                report.add(
                    code="INVALID_RULE_PRIORITY",
                    severity="error",
                    message="Priority must be a positive integer when provided.",
                    path=rule_path,
                    rule_id=rule_id,
                )
            elif priority in seen_priorities:
                report.add(
                    code="DUPLICATE_RULE_PRIORITY",
                    severity="warning",
                    message=(
                        f"Priority {priority} is duplicated by "
                        f"{seen_priorities[priority]}."
                    ),
                    path=rule_path,
                    rule_id=rule_id,
                    recommendation="Use unique priorities for deterministic ordering.",
                )
            else:
                seen_priorities[priority] = rule_path

        paths = _extract_paths(rule)
        path_regexes = _extract_path_regexes(rule)
        methods = _extract_methods(rule)
        cidrs = _extract_ip_cidrs(rule)
        country_codes = _extract_country_codes(rule)
        headers = _extract_headers(rule)

        matcher_count = (
            len(paths)
            + len(path_regexes)
            + len(methods)
            + len(cidrs)
            + len(country_codes)
            + len(headers)
        )
        if matcher_count == 0:
            report.add(
                code="RULE_WITHOUT_MATCHERS",
                severity="warning",
                message="Rule has no explicit match conditions.",
                path=rule_path,
                rule_id=rule_id,
                recommendation="Define path/IP/country/method/header matchers to scope the rule.",
            )

        for regex_value in path_regexes:
            try:
                re.compile(regex_value)
            except re.error as exc:
                report.add(
                    code="INVALID_PATH_REGEX",
                    severity="error",
                    message=f"Invalid path regex '{regex_value}': {exc}",
                    path=rule_path,
                    rule_id=rule_id,
                )

        for method in methods:
            if method not in HTTP_METHODS:
                report.add(
                    code="INVALID_HTTP_METHOD",
                    severity="warning",
                    message=f"Unknown HTTP method '{method}'.",
                    path=rule_path,
                    rule_id=rule_id,
                )

        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                report.add(
                    code="INVALID_IP_CIDR",
                    severity="error",
                    message=f"Invalid IP/CIDR matcher '{cidr}'.",
                    path=rule_path,
                    rule_id=rule_id,
                )

        for country in country_codes:
            if not re.fullmatch(r"[A-Z]{2}", country):
                report.add(
                    code="INVALID_COUNTRY_CODE",
                    severity="warning",
                    message=f"Country code '{country}' should be ISO-3166 alpha-2.",
                    path=rule_path,
                    rule_id=rule_id,
                )

        if action == "rate_limit":
            limit = _extract_rate_limit_value(rule)
            if not isinstance(limit, int) or limit <= 0:
                report.add(
                    code="INVALID_RATE_LIMIT_VALUE",
                    severity="error",
                    message=(
                        "rate_limit action requires a positive 'limit_per_minute' "
                        "or 'rate_limit.requests_per_minute' value."
                    ),
                    path=rule_path,
                    rule_id=rule_id,
                )

        if action == "allow" and _is_broad_allow(paths, path_regexes, cidrs):
            report.add(
                code="BROAD_ALLOW_RULE",
                severity="warning",
                message="Allow rule is broad and may bypass security controls.",
                path=rule_path,
                rule_id=rule_id,
                recommendation=(
                    "Scope the allow rule by path, source IP, headers, or methods."
                ),
            )

        signatures = _path_signatures(paths, path_regexes)
        if not signatures and cidrs:
            signatures = [f"ip:{','.join(cidrs)}"]
        for signature in signatures:
            path_to_actions.setdefault(signature, set()).add(action or "<missing>")

        for endpoint in MANDATORY_SENSITIVE_ENDPOINTS:
            if _matches_endpoint(paths, path_regexes, endpoint):
                if action in {"block", "challenge"}:
                    protected_sensitive_endpoints.add(endpoint)
                elif action in {"allow", "log"}:
                    report.add(
                        code="SENSITIVE_ENDPOINT_WEAK_ACTION",
                        severity="error",
                        message=(
                            f"Sensitive AEM endpoint '{endpoint}' is matched with "
                            f"'{action}' action."
                        ),
                        path=rule_path,
                        rule_id=rule_id,
                        recommendation="Use block or challenge for sensitive internals.",
                    )
                elif action == "rate_limit":
                    report.add(
                        code="SENSITIVE_ENDPOINT_RATE_LIMIT_ONLY",
                        severity="warning",
                        message=(
                            f"Sensitive endpoint '{endpoint}' is only rate-limited, "
                            "not blocked."
                        ),
                        path=rule_path,
                        rule_id=rule_id,
                    )

        if action == "rate_limit":
            for endpoint in LOGIN_ENDPOINTS:
                if _matches_endpoint(paths, path_regexes, endpoint):
                    login_rate_limit_present_ref[0] = True


def _coerce_rule_id(rule: dict[str, Any], *, index: int) -> str:
    for key in ("id", "name", "rule_id"):
        value = rule.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"unnamed-rule-{index + 1}"


def _extract_match(rule: dict[str, Any]) -> dict[str, Any]:
    value = rule.get("match")
    if isinstance(value, dict):
        return value
    return {}


def _extract_paths(rule: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("path", "path_prefix"):
        value = rule.get(key)
        if isinstance(value, str):
            paths.append(value.strip())
        elif isinstance(value, list):
            paths.extend(str(item).strip() for item in value if isinstance(item, str))

    match = _extract_match(rule)
    for key in ("path", "path_prefix"):
        value = match.get(key)
        if isinstance(value, str):
            paths.append(value.strip())
        elif isinstance(value, list):
            paths.extend(str(item).strip() for item in value if isinstance(item, str))

    conditions = rule.get("conditions")
    if isinstance(conditions, list):
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            if condition.get("field") == "path":
                value = condition.get("value")
                if isinstance(value, str):
                    paths.append(value.strip())
    return [path for path in paths if path]


def _extract_path_regexes(rule: dict[str, Any]) -> list[str]:
    regexes: list[str] = []
    value = rule.get("path_regex")
    if isinstance(value, str):
        regexes.append(value.strip())
    elif isinstance(value, list):
        regexes.extend(str(item).strip() for item in value if isinstance(item, str))

    match = _extract_match(rule)
    value = match.get("path_regex")
    if isinstance(value, str):
        regexes.append(value.strip())
    elif isinstance(value, list):
        regexes.extend(str(item).strip() for item in value if isinstance(item, str))

    conditions = rule.get("conditions")
    if isinstance(conditions, list):
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            if condition.get("field") in {"path_regex", "uri_regex"}:
                value = condition.get("value")
                if isinstance(value, str):
                    regexes.append(value.strip())

    return [regex for regex in regexes if regex]


def _extract_methods(rule: dict[str, Any]) -> list[str]:
    methods: list[str] = []
    value = rule.get("methods")
    if isinstance(value, str):
        methods.append(value.upper().strip())
    elif isinstance(value, list):
        methods.extend(str(item).upper().strip() for item in value if isinstance(item, str))

    match = _extract_match(rule)
    value = match.get("methods")
    if isinstance(value, str):
        methods.append(value.upper().strip())
    elif isinstance(value, list):
        methods.extend(str(item).upper().strip() for item in value if isinstance(item, str))
    return [method for method in methods if method]


def _extract_ip_cidrs(rule: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    value = rule.get("ip_cidrs")
    if isinstance(value, str):
        cidrs.append(value.strip())
    elif isinstance(value, list):
        cidrs.extend(str(item).strip() for item in value if isinstance(item, str))

    match = _extract_match(rule)
    value = match.get("ip_cidrs")
    if isinstance(value, str):
        cidrs.append(value.strip())
    elif isinstance(value, list):
        cidrs.extend(str(item).strip() for item in value if isinstance(item, str))
    return [cidr for cidr in cidrs if cidr]


def _extract_country_codes(rule: dict[str, Any]) -> list[str]:
    countries: list[str] = []
    value = rule.get("country_codes")
    if isinstance(value, str):
        countries.append(value.upper().strip())
    elif isinstance(value, list):
        countries.extend(str(item).upper().strip() for item in value if isinstance(item, str))

    match = _extract_match(rule)
    value = match.get("country_codes")
    if isinstance(value, str):
        countries.append(value.upper().strip())
    elif isinstance(value, list):
        countries.extend(str(item).upper().strip() for item in value if isinstance(item, str))
    return [country for country in countries if country]


def _extract_headers(rule: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    value = rule.get("headers")
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                headers[key] = str(item)
    match = _extract_match(rule)
    value = match.get("headers")
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                headers[key] = str(item)
    return headers


def _extract_rate_limit_value(rule: dict[str, Any]) -> int | None:
    direct = rule.get("limit_per_minute")
    if isinstance(direct, int):
        return direct
    nested = rule.get("rate_limit")
    if isinstance(nested, dict):
        value = nested.get("requests_per_minute")
        if isinstance(value, int):
            return value
    return None


def _is_broad_allow(paths: list[str], regexes: list[str], cidrs: list[str]) -> bool:
    if cidrs:
        return False
    if not paths and not regexes:
        return True
    broad_paths = {"*", "/*", "/", "/**"}
    if any(path.strip() in broad_paths for path in paths):
        return True
    if any(regex.strip() in {".*", "^.*$", "^/.*$"} for regex in regexes):
        return True
    return False


def _path_signatures(paths: list[str], regexes: list[str]) -> list[str]:
    signatures: list[str] = [f"path:{path}" for path in paths]
    signatures.extend(f"regex:{regex}" for regex in regexes)
    return signatures


def _matches_endpoint(paths: list[str], regexes: list[str], endpoint: str) -> bool:
    normalized_endpoint = endpoint.rstrip("/")
    for path in paths:
        if _path_covers_endpoint(path, normalized_endpoint):
            return True
    for regex in regexes:
        try:
            if re.search(regex, normalized_endpoint):
                return True
        except re.error:
            continue
    return False


def _path_covers_endpoint(path_pattern: str, endpoint: str) -> bool:
    path_pattern = path_pattern.strip()
    if not path_pattern:
        return False
    if path_pattern in {"*", "/*", "/**"}:
        return True
    if "*" in path_pattern:
        prefix = path_pattern.split("*", 1)[0].rstrip("/")
        return endpoint.startswith(prefix)
    normalized = path_pattern.rstrip("/")
    return endpoint.startswith(normalized)

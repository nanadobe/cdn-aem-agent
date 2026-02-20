"""Deterministic parsing of natural-language security requirements."""

from __future__ import annotations

import re
from typing import Iterable

from .models import ParsedRequirement

COUNTRY_ALIASES = {
    "china": "CN",
    "russia": "RU",
    "iran": "IR",
    "north korea": "KP",
    "korea": "KR",
    "united states": "US",
    "usa": "US",
    "united kingdom": "GB",
    "uk": "GB",
    "germany": "DE",
    "france": "FR",
    "italy": "IT",
    "spain": "ES",
    "canada": "CA",
    "australia": "AU",
    "india": "IN",
    "brazil": "BR",
    "japan": "JP",
    "singapore": "SG",
}

METHOD_PATTERN = r"(?:get|post|put|patch|delete|head|options)"

_RE_RATE_LIMIT_A = re.compile(
    r"(?:rate[\s-]*limit|limit)\s+(?:requests?\s+)?(?:to|for|on)?\s*"
    r"(?P<path>/[^\s,;]+).*?(?P<limit>\d+)\s*(?:requests?)?\s*(?:per|/)\s*"
    r"(?:minute|min|m)\b",
    re.IGNORECASE,
)
_RE_RATE_LIMIT_B = re.compile(
    r"(?P<limit>\d+)\s*(?:requests?)?\s*(?:per|/)\s*(?:minute|min|m)\b.*?"
    r"(?:to|for|on)\s*(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_BLOCK_IP = re.compile(
    r"(?:block|deny)\s+(?:traffic\s+from\s+)?(?P<ips>"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"(?:\s*(?:,|and)\s*(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)*)",
    re.IGNORECASE,
)
_RE_ALLOW_IP = re.compile(
    r"(?:allow|permit)\s+(?:traffic\s+from\s+)?(?P<ips>"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"(?:\s*(?:,|and)\s*(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)*)",
    re.IGNORECASE,
)
_RE_BLOCK_COUNTRY = re.compile(
    r"(?:block|deny)\s+(?:traffic\s+)?(?:from\s+)?(?:countries|country)\s+"
    r"(?P<countries>[a-zA-Z,\s]+)$",
    re.IGNORECASE,
)
_RE_ALLOW_COUNTRY = re.compile(
    r"(?:allow|permit)\s+(?:traffic\s+)?(?:from\s+)?(?:countries|country)\s+"
    r"(?P<countries>[a-zA-Z,\s]+)$",
    re.IGNORECASE,
)
_RE_RESTRICT_METHODS = re.compile(
    rf"restrict\s+(?:methods?\s+)?to\s+(?P<methods>{METHOD_PATTERN}"
    rf"(?:\s*(?:,|and)\s*{METHOD_PATTERN})*)\s+(?:on|for|to)\s+"
    r"(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_ALLOW_METHODS = re.compile(
    rf"(?:only\s+allow|allow)\s+(?P<methods>{METHOD_PATTERN}"
    rf"(?:\s*(?:,|and)\s*{METHOD_PATTERN})*)\s+(?:requests?\s+)?"
    r"(?:on|for|to)\s+(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_REQUIRE_HEADER = re.compile(
    r"(?:require|enforce)\s+header\s+(?P<header>[A-Za-z0-9-]+)"
    r"(?:\s*(?:=|equals)\s*(?P<value>[^\s,;]+))?"
    r".*?(?:for|on)\s+(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_CHALLENGE_PATH = re.compile(
    r"(?:challenge|captcha)\s+(?:bots?|traffic|requests?)\s+(?:on|for|to)\s+"
    r"(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_BLOCK_PATH = re.compile(
    r"(?:block|deny)\s+(?:access\s+to\s+|requests?\s+to\s+|traffic\s+to\s+)?"
    r"(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)
_RE_ALLOW_PATH = re.compile(
    r"(?:allow|permit)\s+(?:access\s+to\s+|requests?\s+to\s+|traffic\s+to\s+)?"
    r"(?P<path>/[^\s,;]+)",
    re.IGNORECASE,
)


def parse_requirements(requirements_text: str) -> list[ParsedRequirement]:
    """Parse multiline requirements text into typed intents."""
    parsed: list[ParsedRequirement] = []
    for requirement in _split_requirements(requirements_text):
        parsed.append(_parse_single_requirement(requirement))
    return parsed


def _split_requirements(text: str) -> Iterable[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for segment in line.split(";"):
            entry = segment.strip()
            if not entry:
                continue
            entry = re.sub(r"^[-*]\s+", "", entry)
            entry = re.sub(r"^\d+[.)]\s+", "", entry)
            if entry:
                yield entry


def _parse_single_requirement(requirement: str) -> ParsedRequirement:
    if match := _RE_RATE_LIMIT_A.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="rate_limit_path",
            params={
                "path": match.group("path"),
                "limit_per_minute": int(match.group("limit")),
            },
            confidence=0.95,
        )
    if match := _RE_RATE_LIMIT_B.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="rate_limit_path",
            params={
                "path": match.group("path"),
                "limit_per_minute": int(match.group("limit")),
            },
            confidence=0.92,
        )
    if match := _RE_BLOCK_IP.search(requirement):
        ip_values = _extract_ip_values(match.group("ips"))
        return ParsedRequirement(
            raw_text=requirement,
            intent="block_ip",
            params={"ip_cidrs": ip_values},
            confidence=0.95,
        )
    if match := _RE_ALLOW_IP.search(requirement):
        ip_values = _extract_ip_values(match.group("ips"))
        return ParsedRequirement(
            raw_text=requirement,
            intent="allow_ip",
            params={"ip_cidrs": ip_values},
            confidence=0.95,
        )
    if match := _RE_BLOCK_COUNTRY.search(requirement):
        countries = _extract_country_codes(match.group("countries"))
        return ParsedRequirement(
            raw_text=requirement,
            intent="block_country",
            params={"country_codes": countries},
            confidence=0.9 if countries else 0.5,
        )
    if match := _RE_ALLOW_COUNTRY.search(requirement):
        countries = _extract_country_codes(match.group("countries"))
        return ParsedRequirement(
            raw_text=requirement,
            intent="allow_country",
            params={"country_codes": countries},
            confidence=0.9 if countries else 0.5,
        )
    if match := _RE_RESTRICT_METHODS.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="allow_methods_path",
            params={
                "path": match.group("path"),
                "methods": _extract_methods(match.group("methods")),
            },
            confidence=0.88,
        )
    if match := _RE_ALLOW_METHODS.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="allow_methods_path",
            params={
                "path": match.group("path"),
                "methods": _extract_methods(match.group("methods")),
            },
            confidence=0.88,
        )
    if match := _RE_REQUIRE_HEADER.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="require_header_path",
            params={
                "path": match.group("path"),
                "header": match.group("header"),
                "header_value": match.group("value") or "required",
            },
            confidence=0.85,
        )
    if match := _RE_CHALLENGE_PATH.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="challenge_path",
            params={"path": match.group("path")},
            confidence=0.8,
        )
    if match := _RE_BLOCK_PATH.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="block_path",
            params={"path": match.group("path")},
            confidence=0.8,
        )
    if match := _RE_ALLOW_PATH.search(requirement):
        return ParsedRequirement(
            raw_text=requirement,
            intent="allow_path",
            params={"path": match.group("path")},
            confidence=0.8,
        )
    return ParsedRequirement(
        raw_text=requirement,
        intent="unknown",
        params={},
        confidence=0.0,
    )


def _extract_methods(text: str) -> list[str]:
    methods = re.findall(METHOD_PATTERN, text, flags=re.IGNORECASE)
    return [method.upper() for method in methods]


def _extract_ip_values(text: str) -> list[str]:
    return re.findall(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", text)


def _extract_country_codes(text: str) -> list[str]:
    candidates = [
        item.strip().lower()
        for item in re.split(r",|\band\b", text)
        if item and item.strip()
    ]
    country_codes: list[str] = []
    for candidate in candidates:
        if re.fullmatch(r"[a-z]{2}", candidate):
            country_codes.append(candidate.upper())
            continue
        resolved = COUNTRY_ALIASES.get(candidate)
        if resolved:
            country_codes.append(resolved)
    return sorted(set(country_codes))

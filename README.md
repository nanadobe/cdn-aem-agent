# AEM WAF/CDN Agent

This project provides a deterministic Python agent to:

1. **Analyze and validate** AEM-focused WAF/CDN rule configs (`cdn.yaml`).
2. **Detect risky or incomplete security posture** based on Adobe's public starter guidance (syntax issues, invalid conditions/actions/rate limits, missing recommended baseline controls, etc.).
3. **Generate rules from natural-language requirements** and merge them back into your `cdn.yaml`.

## Documentation source of truth

Validation and generation behavior is aligned to these Adobe public docs:

- https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf
- https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/content-delivery/cdn-configuring-traffic
- https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/security/traffic-filter-rules-including-waf?lang=en

It validates Adobe syntax including:
- `kind: "CDN"`, `version: "1"`
- `data.trafficFilters.rules`
- `when` condition structure (`allOf` / `anyOf`, getters, predicates)
- `action` structure (`allow` / `block` / `log`, `wafFlags`, `status`, `alert`)
- `rateLimit` structure (`limit`, `window`, `penalty`, `count`, `groupBy`)
- WAF flags and Adobe constraints (for example, `rateLimit` cannot be combined with `wafFlags`)

It also checks for Adobe-recommended baseline starter coverage (edge/origin DoS rate limits, OFAC country blocking rule, ATTACK/ATTACK-FROM-BAD-IP WAF starter rules).

## Privacy behavior

The agent redacts sensitive values in analysis output and generated metadata-facing strings:
- IP/CIDR literals
- token/secret/password-like assignments
- bearer tokens

This helps prevent accidental disclosure of customer-sensitive values in logs/reports.

## Install

```bash
pip install -e .
```

## CLI Usage

### Analyze an existing config

```bash
python -m aem_waf_cdn_agent analyze --cdn-yaml ./cdn.yaml --report-json ./analysis-report.json
```

### Generate rules from natural-language requirements

```bash
python -m aem_waf_cdn_agent generate \
  --cdn-yaml ./cdn.yaml \
  --requirements-file ./requirements.txt \
  --output-cdn-yaml ./cdn.generated.yaml \
  --report-json ./generation-report.json
```

Inline requirements are also supported:

```bash
python -m aem_waf_cdn_agent generate \
  --cdn-yaml ./cdn.yaml \
  --requirement "Block access to /system/console*" \
  --requirement "Rate limit /libs/granite/core/content/login to 60 requests per minute"
```

Note: Adobe `rateLimit.limit` is requests/second. If a requirement is expressed per minute, the generator converts it conservatively to per-second limits.

## Supported natural-language requirement intents

The parser is deterministic and regex-based for predictability.

- Block/deny path (e.g. `Block access to /system/console*`)
- Allow path (e.g. `Allow access to /content/dam/*`)
- Rate-limit path (e.g. `Rate limit /login to 30 requests per minute`)
- Block/allow IPs/CIDRs
- Block/allow countries
- Restrict/allow methods on path
- Require header on path

Unmatched requirements are reported as skipped with a reason.

## Expected generated rule shape (Adobe syntax)

Generated rules use this schema:

```yaml
kind: "CDN"
version: "1"
data:
  trafficFilters:
    rules:
      - name: block-block-path-system-console
        when:
          allOf:
            - reqProperty: path
              like: /system/console*
            - reqProperty: tier
              in: [publish]
        action:
          type: block
```

The analyzer can still discover non-canonical rule paths, but prefers `data.trafficFilters.rules` and warns when rules are in non-standard locations.

## Python API

```python
from aem_waf_cdn_agent import AemWafCdnAgent

agent = AemWafCdnAgent()
report = agent.analyze_file("cdn.yaml")
print(report.to_dict())

result = agent.generate_from_files(
    cdn_yaml_path="cdn.yaml",
    requirements_text="Block access to /system/console*",
    output_yaml_path="cdn.generated.yaml",
)
print(result.generated_rules)
```

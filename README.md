# AEM WAF/CDN Agent

This project provides a deterministic Python agent to:

1. **Analyze and validate** AEM-focused WAF/CDN rule configs (`cdn.yaml`).
2. **Detect risky or incomplete security posture** (schema issues, broad allows, weak protection for sensitive AEM endpoints, missing auth rate limits, etc.).
3. **Generate rules from natural-language requirements** and merge them back into your `cdn.yaml`.

## What "AEM-specific" means in this agent

The analyzer includes baseline checks for common AEM-sensitive surfaces:

- `/system/console`
- `/crx`
- `/etc/packages`
- `/bin/querybuilder`
- auth/login endpoints like `/libs/granite/core/content/login` and `/j_security_check`

It flags missing protections and weak actions (for example, allowing sensitive internals).

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

## Supported natural-language requirement intents

The parser is deterministic and regex-based for predictability.

- Block/deny path (e.g. `Block access to /system/console*`)
- Allow path (e.g. `Allow access to /content/dam/*`)
- Rate-limit path (e.g. `Rate limit /login to 30 requests per minute`)
- Block/allow IPs/CIDRs
- Block/allow countries
- Restrict/allow methods on path
- Require header on path
- Challenge traffic on path

Unmatched requirements are reported as skipped with a reason.

## Expected rule shape

Generated rules use this schema:

```yaml
rules:
  - id: block-block-path-system-console
    description: Generated from requirement: Block access to /system/console*
    action: block
    priority: 100
    match:
      path: /system/console*
    metadata:
      generated_by: aem_waf_cdn_agent
      source_requirement: Block access to /system/console*
```

The analyzer supports common variants (top-level `rules`, `waf.rules`, `cdn.rules`, `data.rules`, etc.).

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

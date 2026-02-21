# MCP-Only Release Guide (Local Test + IDE Consumption)

This branch is an **MCP-only** release of the AEM WAF/CDN agent.

It is designed to be consumed from:

- Cursor
- MCP-compatible IDE assistants
- Any local workflow that can launch an MCP stdio server

---

## 1) What this MCP server can do

The server exposes these tools:

1. `analyze_cdn_yaml` – full analyzer report
2. `analyse_cdn_yaml` – alias for UK spelling
3. `validate_cdn_yaml` – pass/fail validation summary + report
4. `create_analysis_report` – markdown/json report rendering
5. `create_rules_from_requirements` – natural-language to rule generation
6. `add_feature_pack` – inject public-doc-based starter packs
7. `create_custom_rule` – create one structured custom rule
8. `list_feature_packs` – list available feature packs
9. `list_tool_capabilities` – describe tool purposes
10. `get_adobe_reference_docs` – docs used as syntax source-of-truth

---

## 2) Feature packs in this release

Use with `add_feature_pack`:

- `standard_recommended`
  - edge DoS rate limit monitor
  - origin DoS rate limit monitor
  - OFAC country block template
- `waf_recommended`
  - `ATTACK-FROM-BAD-IP` and `ATTACK` starter rules
  - supports `mode=safe|strict`
- `auth_monitoring`
  - monitor AEM publish login/logout endpoints

All packs are derived from Adobe public documentation/tutorial examples.

---

## 3) Local setup

From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

If script entrypoints are not in PATH, use module mode:

```bash
python3 -m aem_waf_cdn_agent.mcp_server
```

---

## 4) Pre-release local validation

### 4.1 Unit tests

```bash
python3 -m unittest discover -s tests -v
```

### 4.2 CLI smoke checks (optional but recommended)

```bash
python3 -m aem_waf_cdn_agent analyze --cdn-yaml ./examples/cdn.sample.yaml
python3 -m aem_waf_cdn_agent generate --cdn-yaml ./examples/cdn.sample.yaml --requirements-file ./examples/requirements.sample.txt --output-cdn-yaml ./examples/cdn.generated.yaml
```

---

## 5) Run MCP server locally

```bash
aem-waf-cdn-agent-mcp
```

or:

```bash
python3 -m aem_waf_cdn_agent.mcp_server
```

This process is long-running and communicates over stdio.

---

## 6) Cursor integration

Use config like this in Cursor MCP settings:

```json
{
  "mcpServers": {
    "aem-cdn-agent": {
      "command": "aem-waf-cdn-agent-mcp",
      "args": []
    }
  }
}
```

If PATH issues occur:

```json
{
  "mcpServers": {
    "aem-cdn-agent": {
      "command": "python3",
      "args": ["-m", "aem_waf_cdn_agent.mcp_server"]
    }
  }
}
```

Reference example: `examples/cursor.mcp.json`

---

## 7) How to use MCP tools in chat/IDE prompts

Examples of intent you can give your assistant:

- "Use `analyze_cdn_yaml` on this `cdn.yaml` and summarize blockers."
- "Use `validate_cdn_yaml` and return only errors."
- "Use `add_feature_pack` with `standard_recommended` and show resulting YAML."
- "Use `add_feature_pack` with `waf_recommended` mode `safe`."
- "Use `create_rules_from_requirements` for these business requirements."
- "Use `create_custom_rule` to block `/system/console*` on publish."
- "Use `create_analysis_report` in markdown format."

### Tool-by-tool example prompts

- Analyze:
  - `Call analyze_cdn_yaml with my current cdn.yaml content and list only errors`
- Validate:
  - `Call validate_cdn_yaml and tell me if config is valid for deployment`
- Create report:
  - `Call create_analysis_report with report_format=markdown`
- Create rules from requirements:
  - `Call create_rules_from_requirements using these requirements...`
- Add feature pack:
  - `Call add_feature with feature_name=standard_recommended`
  - `Call add_feature_pack with feature_name=waf_recommended and mode=safe`
- Create custom rule:
  - `Call create_custom_rule with rule_name=block-admin-console, action_type=block, req_property=path, predicate=like, predicate_value=/system/console*, tier_scope=publish`
- List tools:
  - `Call list_tool_capabilities`
- List feature packs:
  - `Call list_feature_packs`

---

## 8) MCP release checklist

- [ ] `pip install -e .` succeeds
- [ ] unit tests pass
- [ ] MCP server starts locally
- [ ] Cursor detects all tools (`list_tool_capabilities`)
- [ ] sample analyze/generate flow runs without errors
- [ ] docs/source references available (`get_adobe_reference_docs`)

---

## 9) Security notes

- Findings and report payloads are redacted for common sensitive data patterns.
- Avoid placing customer secrets in YAML committed to git.
- Use non-production sample values during demonstrations.

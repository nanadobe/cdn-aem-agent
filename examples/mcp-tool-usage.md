# MCP Tool Usage Examples

Use these prompt patterns in Cursor/IDE after MCP server is connected.

## Analyze and validate

- "Call `analyze_cdn_yaml` with my `cdn.yaml` and summarize high severity findings."
- "Call `validate_cdn_yaml` and tell me if this config can be deployed."

## Add predefined security features

- "Call `add_feature` with `feature_name=standard_recommended`."
- "Call `add_feature_pack` with `feature_name=waf_recommended` and `mode=safe`."
- "Call `list_feature_packs` before applying any pack."

## Create rules

- "Call `create_rules_from_requirements` using this requirements text."
- "Call `create_custom_rule` to block `/system/console*` on publish."

## Create reports

- "Call `create_analysis_report` with `report_format=markdown`."

## Inspect tool catalog and references

- "Call `list_tool_capabilities`."
- "Call `get_adobe_reference_docs`."

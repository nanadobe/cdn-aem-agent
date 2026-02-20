# Local Testing, Hosting, and IDE/Chat Integration Guide

This guide shows how to run the agent locally, verify behavior before production, and expose it for:

- API-based chat interfaces
- Cursor (via MCP)
- Other IDEs/tools that can call HTTP or MCP tools

---

## 1) Prerequisites

- Python 3.11+
- `pip`
- (Optional) Docker

From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

---

## 2) Local validation before hosting

### 2.1 Run unit tests

```bash
python3 -m unittest discover -s tests -v
```

### 2.2 Test with sample files (CLI)

#### Analyze sample config

```bash
python3 -m aem_waf_cdn_agent analyze \
  --cdn-yaml ./examples/cdn.sample.yaml \
  --report-json ./analysis-report.json
```

#### Generate rules from natural language

```bash
python3 -m aem_waf_cdn_agent generate \
  --cdn-yaml ./examples/cdn.sample.yaml \
  --requirements-file ./examples/requirements.sample.txt \
  --output-cdn-yaml ./examples/cdn.generated.yaml \
  --report-json ./generation-report.json
```

Review:

- `analysis-report.json`
- `generation-report.json`
- `examples/cdn.generated.yaml`

---

## 3) Run as HTTP API (for chat interfaces)

The API exposes:

- `GET /health`
- `POST /analyze`
- `POST /generate`

### 3.1 Start API server

```bash
aem-waf-cdn-agent-api
```

or

```bash
uvicorn aem_waf_cdn_agent.api:app --host 0.0.0.0 --port 8080
```

### 3.2 Test API endpoints locally

#### Health

```bash
curl -s http://127.0.0.1:8080/health
```

#### Analyze

```bash
curl -s \
  -X POST "http://127.0.0.1:8080/analyze" \
  -H "Content-Type: application/json" \
  --data @examples/api/analyze-request.json
```

#### Generate

```bash
curl -s \
  -X POST "http://127.0.0.1:8080/generate" \
  -H "Content-Type: application/json" \
  --data @examples/api/generate-request.json
```

### 3.3 OpenAPI docs

While running locally:

- Swagger UI: `http://127.0.0.1:8080/docs`
- OpenAPI JSON: `http://127.0.0.1:8080/openapi.json`

---

## 4) Run as MCP server (for Cursor / MCP IDE integrations)

### 4.1 Start MCP server (stdio transport)

```bash
aem-waf-cdn-agent-mcp
```

This exposes tools:

- `analyze_cdn_yaml`
- `generate_cdn_rules`
- `get_adobe_reference_docs`

### 4.2 Configure Cursor

Use this as a base in Cursor MCP config (adapt path/command to your environment):

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

Sample file: `examples/cursor.mcp.json`

---

## 5) Dockerized local test

### 5.1 Build image

```bash
docker build -t aem-waf-cdn-agent:local .
```

### 5.2 Run container

```bash
docker run --rm -p 8080:8080 aem-waf-cdn-agent:local
```

Then test API with the same curl commands from section 3.

---

## 6) Hosting options for production

Use the API runtime for production hosting.

Common choices:

- Kubernetes
- AWS ECS/Fargate
- Azure Container Apps
- Google Cloud Run
- Render/Fly.io/Railway

### Recommended production controls

1. Add auth (API key or JWT).
2. Restrict ingress (private network, allowlists, WAF).
3. Add request size limits and timeouts.
4. Disable raw payload logging; keep only redacted findings.
5. Pin image tags and use CI vulnerability scanning.
6. Add health/readiness probes (`/health`).
7. Add monitoring and alerting.

---

## 7) Suggested pre-production checklist

- [ ] Unit tests pass
- [ ] Analyze/generate validated on sample and your real non-sensitive config
- [ ] API contract tested from your chat interface
- [ ] MCP tools visible and callable in Cursor
- [ ] Auth and network protections enabled
- [ ] Logging policy verified (no sensitive payload leakage)
- [ ] Rollback plan prepared

---

## 8) Typical integration patterns

### Pattern A: Chat interface via HTTP tools

Your chat backend calls:

- `/analyze` for validation
- `/generate` for rule synthesis

### Pattern B: Cursor IDE via MCP

Cursor calls MCP tools directly from prompt context.

### Pattern C: Hybrid

- MCP for developer workflows in IDE
- HTTP API for broader platform/chat consumers


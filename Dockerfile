FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY aem_waf_cdn_agent ./aem_waf_cdn_agent

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "aem_waf_cdn_agent.api:app", "--host", "0.0.0.0", "--port", "8080"]

"""FastAPI hosting layer for the AEM WAF/CDN agent."""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .service import analyze_yaml_text, generate_from_yaml_text

app = FastAPI(
    title="AEM WAF/CDN Agent API",
    version="0.1.0",
    description=(
        "Analyze and generate AEM CDN traffic filter rules from YAML and "
        "natural-language requirements."
    ),
)


class AnalyzeRequest(BaseModel):
    cdn_yaml: str = Field(..., description="Raw cdn.yaml text")


class GenerateRequest(BaseModel):
    cdn_yaml: str = Field(..., description="Raw cdn.yaml text")
    requirements_text: str = Field(
        ..., description="Natural-language requirements, one or more lines"
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "aem-waf-cdn-agent"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    try:
        return analyze_yaml_text(request.cdn_yaml)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/generate")
def generate(request: GenerateRequest) -> dict:
    try:
        return generate_from_yaml_text(request.cdn_yaml, request.requirements_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def run() -> None:
    """Run API server with uvicorn (script entrypoint)."""
    import uvicorn

    host = os.getenv("AEM_AGENT_HOST", "0.0.0.0")
    port = int(os.getenv("AEM_AGENT_PORT", "8080"))
    uvicorn.run("aem_waf_cdn_agent.api:app", host=host, port=port)


if __name__ == "__main__":
    run()

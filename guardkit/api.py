"""FastAPI service for guardkit (optional extra: pip install "guardkit[api]").

    GUARDKIT_POLICY=policy.yaml GUARDKIT_API_KEY=secret \
      uvicorn guardkit.api:create_app_from_env --factory --host 0.0.0.0 --port 8080

Endpoints
    GET  /health
    POST /v1/check   {"text": "...", "stage": "input"|"output"}  -> action, redacted text, findings
    POST /v1/redact  {"text": "..."}                              -> PII/secrets redacted regardless of policy
If an API key is configured every /v1 call must send it in the X-API-Key header. Matched values are never
echoed in findings. Terminate TLS in front of the service (reverse proxy / platform); it speaks plain HTTP.
"""
import hmac
import os
from typing import Any, Dict, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .mcp_server import DEFAULT_POLICY
from .pipeline import Pipeline
from .policy import from_dict, load

MAX_CHARS = 100_000


class CheckRequest(BaseModel):
    text: str = Field(..., max_length=MAX_CHARS)
    stage: Literal["input", "output"] = "input"


class RedactRequest(BaseModel):
    text: str = Field(..., max_length=MAX_CHARS)


def create_app(pipeline: Optional[Pipeline] = None, api_key: Optional[str] = None) -> FastAPI:
    pipe = pipeline or from_dict(DEFAULT_POLICY)
    redactor = from_dict({"input": [{"guard": "secrets", "action": "redact"},
                                    {"guard": "pii", "action": "redact"}]})
    app = FastAPI(title="guardkit", version=__version__)

    def auth(x_api_key: Optional[str] = Header(default=None)) -> None:
        if api_key and not (x_api_key and hmac.compare_digest(x_api_key, api_key)):
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/check", dependencies=[Depends(auth)])
    def check(req: CheckRequest) -> Dict[str, Any]:
        fn = pipe.check_input if req.stage == "input" else pipe.check_output
        return fn(req.text).to_dict()

    @app.post("/v1/redact", dependencies=[Depends(auth)])
    def redact(req: RedactRequest) -> Dict[str, Any]:
        return redactor.check_input(req.text).to_dict()

    return app


def create_app_from_env() -> FastAPI:
    policy = os.environ.get("GUARDKIT_POLICY")
    return create_app(load(policy) if policy else None, os.environ.get("GUARDKIT_API_KEY") or None)

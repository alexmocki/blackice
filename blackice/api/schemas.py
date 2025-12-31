from __future__ import annotations

from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


AuditMode = Literal["off", "warn", "strict"]


class RunRequest(BaseModel):
    events_jsonl: str = Field(..., description="Input events as JSONL text")
    audit_mode: AuditMode = Field("warn", description="Normalization audit policy")
    normalize: bool = Field(True, description="Normalize decisions output")

    # Pydantic v2 style config for adding OpenAPI examples

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "events_jsonl": "{\"event\": \"...\"}\n",
                "audit_mode": "strict",
                "normalize": True,
            }
        }
    )


class Artifacts(BaseModel):
    alerts_jsonl: str
    decisions_jsonl: str
    trust_jsonl: str


class RunResponse(BaseModel):
    ok: bool = True
    request_id: str
    artifacts: Artifacts
    summary: Dict[str, Any]


class ErrorResponse(BaseModel):
    ok: bool = False
    request_id: str
    error: Dict[str, Any]
    hint: Optional[str] = None

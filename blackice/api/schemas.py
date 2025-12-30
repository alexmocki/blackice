from pydantic import BaseModel, Field
from typing import Optional, Literal


class RunRequest(BaseModel):
    events_jsonl: str = Field(..., description="Input events in JSONL format")
    audit_mode: Literal["off", "warn", "strict"] = "off"
    normalize: bool = True


class RunArtifacts(BaseModel):
    alerts_jsonl: str
    decisions_jsonl: str
    trust_jsonl: Optional[str] = None


class RunResponse(BaseModel):
    ok: bool
    artifacts: RunArtifacts
    audit: Optional[dict] = None

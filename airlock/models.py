from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    SECRET = "secret"
    UNKNOWN = "unknown"


class Authorization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str
    scope: str
    destination: str | None = None
    explicit: bool = True


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: Any
    sources: list[str] = Field(default_factory=list, max_length=32)
    trust: Trust = Trust.UNKNOWN
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    transformations: list[str] = Field(default_factory=list, max_length=32)
    authorization: Authorization | None = None

    @field_validator("sources", "transformations")
    @classmethod
    def bounded_items(cls, items: list[str]) -> list[str]:
        if any(len(item) > 200 for item in items):
            raise ValueError("provenance metadata item is too long")
        return items

    def safe(self) -> dict[str, Any]:
        return {
            "sources": self.sources,
            "trust": self.trust.value,
            "sensitivity": self.sensitivity.value,
            "transformations": self.transformations,
            "authorization": self.authorization.model_dump() if self.authorization else None,
        }


class ReaderOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=2000)
    relevant_facts: list[str] = Field(default_factory=list, max_length=20)
    requested_action: str | None = Field(default=None, max_length=500)
    claimed_recipient: str | None = Field(default=None, max_length=320)
    claimed_file_path: str | None = Field(default=None, max_length=500)
    potentially_malicious: bool
    source_id: str = Field(min_length=1, max_length=200)


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    operation: Literal[
        "email.search", "email.read", "email.draft", "email.send", "email.forward",
        "files.list", "files.read", "web.search", "content.summarize"
    ]
    args: dict[str, Any] = Field(default_factory=dict, max_length=12)
    depends_on: list[str] = Field(default_factory=list, max_length=8)


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["1"] = "1"
    steps: list[Step] = Field(min_length=1, max_length=12)

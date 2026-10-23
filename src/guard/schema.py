from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal[
    "secret_access", "data_exfiltration", "destructive_command",
    "persistence_or_privesc", "obfuscated_execution", "dependency_risk",
    "resource_exhaustion", "ssrf_network_exfil", "ai_targeted_instructions",
]
Language = Literal["python", "bash", "sql", "javascript", "yaml", "markdown"]
MAX_CODE_LENGTH = 65536
MAX_CODE_LINES = 5000


class CodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    idx: int | str | None = None
    code: str = Field(min_length=1, max_length=MAX_CODE_LENGTH)

    @field_validator("code")
    @classmethod
    def reject_blank(cls, value):
        if not value.strip():
            raise ValueError("code must not be blank")
        if value.count("\n") + 1 > MAX_CODE_LINES:
            raise ValueError(f"code must not exceed {MAX_CODE_LINES} lines")
        return value


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snippets: list[CodeRequest] = Field(min_length=1, max_length=100)


class Verdict(BaseModel):
    verdict: Literal["allow", "block"]
    risk_score: float | None = Field(ge=0, le=1)
    confidence_score: float | None = Field(default=None, ge=0, le=1)
    categories: list[Category]
    code_language: Language
    reason: str
    vulnerable_lines: list[int]


class MitreReference(BaseModel):
    model_config = ConfigDict(frozen=True)
    category: Category
    tactic: str
    tactic_id: str
    technique_id: str
    technique_name: str
    cwe_id: str
    url: str


@dataclass(frozen=True)
class Finding:
    category: Category
    reason: str
    line: int
    score: float | None = None
    mitre: MitreReference | None = None


@dataclass(frozen=True)
class Inspection:
    verdict: Verdict
    findings: list[Finding]
    confidence_score: float | None
    confidence_basis: str
    mitre_techniques: list[MitreReference] = field(default_factory=list)
    breakdown: dict = field(default_factory=dict)

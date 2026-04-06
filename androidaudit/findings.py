from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    cvss_vector: str
    cvss_score: float
    owasp_category: str
    description: str
    evidence: str
    remediation: str
    module: str
    file_path: str | None = None
    line_number: int | None = None
    tags: list[str] = field(default_factory=list)

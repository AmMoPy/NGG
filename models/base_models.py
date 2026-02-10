from enum import Enum
from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Any, Optional


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class FindingType(str, Enum):
    LOGIC = "Logic"
    PROCESS = "Process"
    DEPENDENCY = "Dependency" # For future extensibility
    IAC = "IaC"               # For future extensibility


class Finding(BaseModel):
    id: str
    type: FindingType
    status: FindingStatus
    control: str # The control objective or description
    evidence: Dict[str, Any] # Flexible evidence structure (e.g., file paths, messages, git output)


class AuditResult(BaseModel):
    type: FindingType
    findings: List[Finding]
    stats: Dict[Literal["pass", "fail"], int] # e.g., {"pass": 5, "fail": 2}
    metadata: Dict[str, Any]


class ControlDefinition(BaseModel):
    id: str
    objective: str
    category: str
    verification_method: Optional[str] = None # Might be None for purely process checks


class PatternDefinition(BaseModel):
    id: str
    message: str
    languages: List[str]
    severity: str
    patterns: List[Dict[str, Any]] # More specific sub-models could be added for patterns if needed
    paths: Optional[Dict[str, List[str]]] = None # e.g., {"include": [...], "exclude": [...]}


class CompiledRule(BaseModel):
    control_definition: ControlDefinition
    pattern_definition: Optional[PatternDefinition] = None # Can be None if no code pattern


class AuditResultsSummary(BaseModel):
    findings: List[Finding] = Field(default_factory=list)
    stats: Dict[Literal["pass", "fail"], int] = Field(
        default_factory=lambda: {"pass": 0, "fail": 0}
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def clear(self):
        """Resets all fields to their original default values"""
        for name, field in self.model_fields.items():
            if field.default_factory:
                # Re-run the factory to get a fresh list/dict
                setattr(self, name, field.default_factory())
            else:
                setattr(self, name, field.default)
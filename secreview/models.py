"""Core data structures shared across the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ["high", "medium", "low"]
STATUSES = ["confirmed", "needs_validation"]


@dataclass
class SourceFile:
    path: str  # repo-relative, forward slashes
    language: str
    content: str

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()

    def numbered(self) -> str:
        return "\n".join(f"{i:>4} | {line}" for i, line in enumerate(self.lines, 1))


@dataclass
class Signal:
    """A lead raised by the deterministic rule engine. Not a finding until verified."""

    id: str
    rule_id: str
    title: str
    category: str
    cwe: str
    severity: str
    file: str
    line: int
    snippet: str
    hint: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RelatedLocation:
    file: str
    line: int
    note: str


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    cwe: str
    file: str
    start_line: int
    end_line: int
    evidence: str
    description: str
    impact: str
    remediation: str
    secure_code: str = ""
    secure_code_language: str = ""
    owasp: str = ""
    exploit_scenario: str = ""
    confidence: str = "medium"
    status: str = "needs_validation"
    assumptions: str = ""
    related_locations: list[RelatedLocation] = field(default_factory=list)
    signal_ids: list[str] = field(default_factory=list)
    source: str = "ai"  # "ai", "ai+rules", or "rules"
    review_note: str = ""
    id: str = ""
    grounded: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        rel = [RelatedLocation(**r) for r in d.pop("related_locations", []) or []]
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        clean = {k: v for k, v in d.items() if k in known}
        f = cls(**clean)
        f.related_locations = rel
        return f


@dataclass
class ScanResult:
    target_name: str
    target_source: str
    scanned_at: str
    tool_name: str
    tool_version: str
    mode: str  # "ai" or "rules-only"
    model: str
    files: list[SourceFile]
    signals: list[Signal]
    findings: list[Finding]
    dismissed_signals: list[dict[str, str]] = field(default_factory=list)
    executive_summary: str = ""
    overall_risk: str = ""
    overall_assessment: str = ""
    positive_observations: list[str] = field(default_factory=list)
    prioritized_actions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_source": self.target_source,
            "scanned_at": self.scanned_at,
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "mode": self.mode,
            "model": self.model,
            "files_scanned": [f.path for f in self.files],
            "severity_counts": self.severity_counts(),
            "overall_risk": self.overall_risk,
            "executive_summary": self.executive_summary,
            "overall_assessment": self.overall_assessment,
            "positive_observations": self.positive_observations,
            "prioritized_actions": self.prioritized_actions,
            "limitations": self.limitations,
            "findings": [f.to_dict() for f in self.findings],
            "static_signals": [s.to_dict() for s in self.signals],
            "dismissed_signals": self.dismissed_signals,
            "stats": self.stats,
        }

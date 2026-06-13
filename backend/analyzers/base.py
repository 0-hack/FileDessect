"""Core types shared across every analyzer.

The analysis pipeline is built from independent *analyzers*. Each one looks at
a file (and the metadata gathered so far) and emits zero or more *findings*.
A finding carries a severity weight; the engine sums those weights to derive
an overall verdict (clean / suspicious / malicious) and an explanation built
from the findings themselves.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Severity of an individual finding, ordered by weight."""

    INFO = 0
    LOW = 10
    MEDIUM = 30
    HIGH = 60
    CRITICAL = 100

    @property
    def label(self) -> str:
        return self.name.lower()


class Verdict(str, enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single observation about a file.

    Attributes:
        id: stable machine identifier, e.g. ``pe.packer.upx``.
        title: short human-readable headline.
        description: why this matters / what was observed.
        severity: contribution to the overall risk score.
        category: grouping such as ``executable``, ``embedded``, ``reputation``.
        data: optional structured evidence for the UI / API consumers.
    """

    id: str
    title: str
    description: str
    severity: Severity
    category: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.label,
            "severity_weight": int(self.severity),
            "category": self.category,
            "data": self.data,
        }


@dataclass
class AnalyzerResult:
    """Output of one analyzer: its findings plus any raw metadata it gathered."""

    analyzer: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def add(
        self,
        id: str,
        title: str,
        description: str,
        severity: Severity,
        category: str,
        **data: Any,
    ) -> Finding:
        finding = Finding(
            id=id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            data=data,
        )
        self.findings.append(finding)
        return finding

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "error": self.error,
        }


@dataclass
class FileContext:
    """Everything an analyzer needs to inspect a file.

    ``metadata`` is shared and mutable: earlier analyzers (notably the identity
    analyzer) populate it with hashes, MIME type, etc. so later analyzers can
    branch on it without re-computing.
    """

    path: str
    filename: str
    size: int
    data: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


class Analyzer:
    """Base class for analyzers.

    Subclasses set ``name`` and implement :meth:`run`. They may override
    :meth:`applies` to skip files they do not handle (e.g. the PE analyzer
    only runs on PE binaries).
    """

    name: str = "analyzer"

    def applies(self, ctx: FileContext) -> bool:  # noqa: ARG002
        return True

    def run(self, ctx: FileContext) -> AnalyzerResult:  # pragma: no cover
        raise NotImplementedError

    def _result(self) -> AnalyzerResult:
        return AnalyzerResult(analyzer=self.name)

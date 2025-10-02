from dataclasses import dataclass, field
from typing import Optional, Any
from pathlib import Path
from enum import Enum

from ..configuration import MAX_LINES_FUNCTION



class SeverityLevel(Enum):
    """Levels of issue severity."""

    INFO = "info"
    WARNING = "warning" 
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CodeIssue:
    """Represents a single code issue found during analysis."""

    file: Path
    line: int
    message: str
    severity: SeverityLevel
    rule_id: Optional[str] = None
    suggestion: Optional[str] = None
    context: Optional[str] = None


    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""

        return {
            "file": str(self.file),
            "line": self.line,
            "message": self.message,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "suggestion": self.suggestion,
            "context": self.context
        }


@dataclass
class Rule:
    """Code analysis rule configuration."""

    id: str
    name: str
    description: str
    enabled: bool = True
    severity: SeverityLevel = SeverityLevel.WARNING
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class GitContext:
    """Git repository context information."""

    repo_path: Path
    current_branch: str
    has_uncommitted_changes: bool
    staged_files: list[Path] = field(default_factory=list)
    modified_files: list[Path] = field(default_factory=list)
    untracked_files: list[Path] = field(default_factory=list)
    remote_url: Optional[str] = None


class ReviewConfig:
    """Configuration for code review analysis."""

    def __init__(
        self,
        rules: Optional[dict[str, Rule]] = None,
        ignore_patterns: Optional[list[str]] = None,
        exclude_paths: Optional[list[str]] = None,
        max_line_length: int = 100,
        strict: bool = False,
        output_format: str = "text"
    ) -> None:

        self.rules = rules or self._get_default_rules()
        self.ignore_patterns = ignore_patterns or []
        self.exclude_paths = exclude_paths or []
        self.max_line_length = max_line_length
        self.strict = strict
        self.output_format = output_format


    def _get_default_rules(self) -> dict[str, Rule]:
        # Initialize default rules if none provided

        return {
            "magic_number": Rule(
                id="magic_number",
                name="Magic Number Detection",
                description="Find unnamed numerical constants in code",
                severity=SeverityLevel.WARNING
            ),

            "long_function": Rule(
                id="long_function", 
                name="Long Function Detection",
                description="Identify functions that are too long",
                severity=SeverityLevel.INFO,
                parameters={"max_lines": MAX_LINES_FUNCTION}
            ),

            "unused_import": Rule(
                id="unused_import",
                name="Unused Import Detection", 
                description="Find imports that are not used",
                severity=SeverityLevel.WARNING
            ),
        }


class AnalysisResult:
    """Results of code analysis."""

    def __init__(
        self,
        issues: Optional[list[CodeIssue]] = None,
        files_analyzed: int = 0,
        total_issues: int = 0,
        duration: float = 0.0
    ) -> None:

        self.issues = issues or []
        self.files_analyzed = files_analyzed
        self.total_issues = total_issues
        self.duration = duration


    def add_issue(self, issue: CodeIssue) -> None:
        """Add an issue to results."""
        self.issues.append(issue)
        self.total_issues += 1


    def get_issues_by_severity(self, severity: SeverityLevel) -> list[CodeIssue]:
        """Get issues filtered by severity."""
        return [issue for issue in self.issues if issue.severity == severity]


    def get_summary(self) -> dict[SeverityLevel, int]:
        """Get summary of issues by severity."""
        summary = {}
        for severity in SeverityLevel:
            summary[severity] = len(self.get_issues_by_severity(severity))
        return summary
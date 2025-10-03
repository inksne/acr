from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import json

from .helpers import get_severity_icon, strip_rich_tags, get_summary_table, get_stats_table
from ..core import CodeIssue, SeverityLevel, AnalysisResult



console = Console()


def print_rich_report(issues: list[CodeIssue]) -> None:
    """Print formatted report using Rich."""
    if not issues:
        console.print(Panel.fit("🎉 [bold green]No issues found![/bold green]", border_style="green"))

        return


    by_severity: dict[SeverityLevel, list[CodeIssue]] = {}
    for issue in issues:
        by_severity.setdefault(issue.severity, []).append(issue)

    severity_styles: dict[SeverityLevel, str] = {
        SeverityLevel.INFO: "blue",
        SeverityLevel.WARNING: "yellow",
        SeverityLevel.ERROR: "red",
        SeverityLevel.CRITICAL: "bold red"
    }

    summary_table = get_summary_table(severity_styles, by_severity)

    console.print(Panel(summary_table, title="📊 [bold]Code Review Summary[/bold]"))


    for severity, severity_issues in by_severity.items():
        if not severity_issues:
            continue

        style = severity_styles.get(severity, "white")
        console.print(f"\n[bold {style}]{severity.value.upper()} ISSUES ({len(severity_issues)})[/bold {style}]")
        
        for issue in severity_issues:
            issue_text = Text()
            issue_text.append(f"  {get_severity_icon(issue.severity)} ", style=style)
            issue_text.append(f"{issue.file}:{issue.line} - ", style="cyan")
            issue_text.append(issue.message)
            
            if issue.suggestion:
                suggestion_text = Text()
                suggestion_text.append("     💡 ", style="green")
                suggestion_text.append(issue.suggestion, style="dim green")
                console.print(issue_text)
                console.print(suggestion_text)

            else:
                console.print(issue_text)


def print_text_report(issues: list[CodeIssue]) -> None:
    """Print simple text format report."""
    if not issues:
        print("✅ No issues found!")
        return


    by_severity: dict[SeverityLevel, list[CodeIssue]] = {}
    for issue in issues:
        by_severity.setdefault(issue.severity, []).append(issue)

    print("Code Review Report")
    print("=" * 50)

    for severity, severity_issues in by_severity.items():
        print(f"\n{severity.value.upper()} ({len(severity_issues)}):")

        for issue in severity_issues:
            print(f"  {get_severity_icon(issue.severity)} {issue.file}:{issue.line} - {strip_rich_tags(issue.message)}")

            if issue.suggestion:
                print(f"     💡 {strip_rich_tags(issue.suggestion)}")


def print_json_report(issues: list[CodeIssue]) -> None:
    """Print JSON format report."""
    issues_data = [issue.to_dict() for issue in issues]

    report = {
        "summary": {
            "total_issues": len(issues),
            "by_severity": {
                severity.value: len([i for i in issues if i.severity == severity])
                for severity in SeverityLevel
            }
        },
        "issues": issues_data
    }

    print(json.dumps(report, indent=2))


def print_report(issues: list[CodeIssue], output_format: str = "rich") -> None:
    """Print analysis report in specified format."""
    if output_format == "json":
        print_json_report(issues)

    elif output_format == "text":
        print_text_report(issues)

    else:
        print_rich_report(issues)


def print_json_analysis_result(result: AnalysisResult) -> None:
    """Print analysis result in JSON format."""
    result_data = {
        "statistics": {
            "files_analyzed": result.files_analyzed,
            "total_issues": result.total_issues,
            "duration": result.duration,
            "summary": {severity.value: count for severity, count in result.get_summary().items()}
        },
        "issues": [issue.to_dict() for issue in result.issues]
    }
    print(json.dumps(result_data, indent=2))


def print_rich_analysis_result(result: AnalysisResult) -> None:
    """Print analysis result with Rich formatting."""

    stats_table = get_stats_table(result)

    console.print(Panel(stats_table, title="📈 [bold]Analysis Statistics[/bold]"))

    print_report(result.issues, "rich")


def print_analysis_result(result: AnalysisResult, output_format: str = "rich") -> None:
    """Print full analysis result with statistics."""
    if output_format == "json":
        print_json_analysis_result(result)

    else:
        print_rich_analysis_result(result)
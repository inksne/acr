from rich.table import Table

from ..core import AnalysisResult, ReviewConfig, CodeIssue, SeverityLevel



def get_severity_icon(severity: SeverityLevel) -> str:
    """Get icon for severity level."""
    icons = {
        SeverityLevel.INFO: "🔵",
        SeverityLevel.WARNING: "🟡",
        SeverityLevel.ERROR: "🔴",
        SeverityLevel.CRITICAL: "💥"
    }

    return icons.get(severity, "⚪")


def strip_rich_tags(text: str) -> str:
    """Remove Rich markup tags from text."""
    import re
    return re.sub(r'\[.*?\]', '', text)


def get_severity_color(severity: SeverityLevel) -> str:
    """Get color for severity level."""
    colors = {
        SeverityLevel.INFO: "blue",
        SeverityLevel.WARNING: "yellow",
        SeverityLevel.ERROR: "red",
        SeverityLevel.CRITICAL: "bold red"
    }

    return colors.get(severity, "white")


def get_summary_table(severity_styles: dict[SeverityLevel, str], by_severity: dict[SeverityLevel, list[CodeIssue]] = {}) -> Table:
    """Returns summary table."""
    summary_table = Table(show_header=True, header_style="bold magenta", padding=(0, 1), width=40)

    summary_table.add_column("Severity", style="cyan")
    summary_table.add_column("Count", justify="center")
    summary_table.add_column("Status", justify="center")

    for severity in SeverityLevel:
        count = len(by_severity.get(severity, []))
        style = severity_styles.get(severity, "white")
        
        if count == 0:
            status = "✅"

        elif severity in [SeverityLevel.ERROR, SeverityLevel.CRITICAL]:
            status = "❌"

        else:
            status = "⚠️"
        
        summary_table.add_row(
            f"[{style}]{severity.value}[/{style}]",
            str(count),
            status
        )

    return summary_table


def get_stats_table(result: AnalysisResult) -> Table:
    """Returns stats table."""
    stats_table = Table(show_header=False, box=None)

    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="white")

    stats_table.add_row("Files analyzed", str(result.files_analyzed))
    stats_table.add_row("Total issues", str(result.total_issues))
    stats_table.add_row("Analysis duration", f"{result.duration:.2f}s")

    summary = result.get_summary()

    for severity, count in summary.items():
        style = {
            SeverityLevel.INFO: "blue",
            SeverityLevel.WARNING: "yellow",
            SeverityLevel.ERROR: "red",
            SeverityLevel.CRITICAL: "bold red"
        }.get(severity, "white")

        stats_table.add_row(f"{severity.value} issues", f"[{style}]{count}[/{style}]")

    return stats_table


def get_main_table(config: ReviewConfig) -> Table:
    """Returns main table."""
    main_table = Table(show_header=False, box=None)

    main_table.add_column("Setting", style="cyan")
    main_table.add_column("Value", style="white")
    
    main_table.add_row("Max line length", str(config.max_line_length))
    main_table.add_row("Strict mode", "✅" if config.strict else "❌")
    main_table.add_row("Output format", config.output_format)

    return main_table


def get_rules_table(config: ReviewConfig) -> Table:
    """Returns rules table."""
    rules_table = Table(show_header=True, header_style="bold magenta")

    rules_table.add_column("Rule ID", style="cyan")
    rules_table.add_column("Name", style="white")
    rules_table.add_column("Enabled", justify="center")
    rules_table.add_column("Severity", justify="center")

    for rule_id, rule in config.rules.items():
        rules_table.add_row(
            rule_id,
            rule.name,
            "✅" if rule.enabled else "❌",
            f"[{get_severity_color(rule.severity)}]{rule.severity.value}[/{get_severity_color(rule.severity)}]"
        )

    return rules_table
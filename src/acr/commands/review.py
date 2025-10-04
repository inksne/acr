from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel

from ..core import CodeAnalyzer, ReviewConfig, AnalysisResult
from ..utils import load_config, find_config_file, print_analysis_result



app = typer.Typer(name="review", help="🔍 Code analysis commands", no_args_is_help=True, rich_markup_mode="rich")

console = Console()


@app.command()
def current(
    path: str = typer.Argument(".", help="[bold green]Path[/bold green] to git repository"),
    config_file: str = typer.Option(None, "--config", "-c", help="[yellow]Config file[/yellow] path"),
    output_format: str = typer.Option("rich", "--output", "-o", help="[blue]Output format[/blue]: rich, text, json", show_choices=True),
    strict: bool = typer.Option(False, "--strict", "-s", help="[red]Fail on warnings[/red]")
) -> None:
    """
    [bold]Analyze current changes[/bold] in git repository.

    Scans modified, staged, and untracked files for code quality issues.

    [dim]Examples:[/dim]
      [cyan]acr review current[/cyan]
      [cyan]acr review current /path/to/repo --strict --output json[/cyan]
    """
    try:
        target_path = Path(path)
        config_path: Optional[Path] = None

        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                console.print(f"⚠️  [yellow]Config file not found: {config_path}, using defaults[/yellow]")
                config_path = None

        else:
            config_path = find_config_file(target_path)

        config = load_config(config_path)
        config.strict = strict


        if config_path and config_path.exists():
            console.print(f"⚙️  [dim]Using config: {config_path}[/dim]")
    
        else:
            console.print("⚙️  [dim]Using default configuration[/dim]")

        analyzer = CodeAnalyzer(config)

        console.print(
            Panel.fit(f"🔍 [bold]Analyzing Git changes in[/bold] [green]{target_path}[/green]", border_style="blue")
        )


        issues = analyzer.analyze_git_changes()

        result = AnalysisResult(
            issues=issues,
            files_analyzed=len(set(issue.file for issue in issues)),
            total_issues=len(issues)
        )

        print_analysis_result(result, output_format)


        if strict and issues:
            console.print(Panel.fit("❌ [bold red]Strict mode enabled - issues found[/bold red]", border_style="red"))
            raise typer.Exit(1)


    except ValueError as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    except Exception as e:
        console.print(f"❌ [bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(1)

@app.command()
def file(
    file_path: str = typer.Argument(..., help="[bold green]File[/bold green] to analyze"),
    config_file: str = typer.Option(None, "--config", "-c", help="[yellow]Config file[/yellow] path"),
    output_format: str = typer.Option("rich", "--output", "-o", help="[blue]Output format[/blue]: rich, text, json", show_choices=True),
    strict: bool = typer.Option(False, "--strict", "-s", help="[red]Fail on warnings[/red]")
) -> None:
    """
    [bold]Analyze specific file[/bold] for code quality issues.
    
    [dim]Examples:[/dim]
      [cyan]acr review file src/main.py[/cyan]
      [cyan]acr review file utils.py --strict[/cyan]
    """
    try:
        target_file = Path(file_path)
        config_path: Optional[Path] = None

        if not target_file.exists():
            console.print(f"❌ [bold red]File not found:[/bold red] {target_file}")
            raise typer.Exit(1)
        
        if target_file.suffix != '.py':
            console.print(f"❌ [bold red]Error:[/bold red] {target_file} is not a Python file (.py)")
            console.print("💡 [yellow]ACR currently only supports Python file analysis[/yellow]")
            raise typer.Exit(1)


        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                console.print(f"⚠️  [yellow]Config file not found: {config_path}, using defaults[/yellow]")
                config_path = None

        else:
            config_path = find_config_file(target_file.parent)

        config = load_config(config_path)
        config.strict = strict


        if config_path and config_path.exists():
            console.print(f"⚙️  [dim]Using config: {config_path}[/dim]")
    
        else:
            console.print("⚙️  [dim]Using default configuration[/dim]")
        

        analyzer = CodeAnalyzer(config)

        console.print(Panel.fit(f"🔍 [bold]Analyzing file[/bold] [green]{target_file}[/green]", border_style="blue"))

        issues = analyzer.analyze_file(target_file)

        result = AnalysisResult(issues=issues, files_analyzed=1, total_issues=len(issues))

        print_analysis_result(result, output_format)


        if strict and issues:
            console.print(Panel.fit("❌ [bold red]Strict mode enabled - issues found[/bold red]", border_style="red"))
            raise typer.Exit(1)


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def directory(
    directory_path: str = typer.Argument(".", help="[bold green]Directory[/bold green] to analyze"),
    config_file: str = typer.Option(None, "--config", "-c", help="[yellow]Config file[/yellow] path"),
    output_format: str = typer.Option("rich", "--output", "-o", help="[blue]Output format[/blue]: rich, text, json",show_choices=True),
    strict: bool = typer.Option(False, "--strict", "-s", help="[red]Fail on warnings[/red]")
) -> None:
    """
    [bold]Analyze all Python files[/bold] in directory recursively.
    
    [dim]Examples:[/dim]
      [cyan]acr review directory .[/cyan]
      [cyan]acr review directory src/ --output json[/cyan]
    """
    try:
        target_dir = Path(directory_path)
        config_path: Optional[Path] = None

        if not target_dir.exists():
            console.print(f"❌ [bold red]Directory not found:[/bold red] {target_dir}")
            raise typer.Exit(1)

        if not target_dir.is_dir():
            console.print(f"❌ [bold red]Not a directory:[/bold red] {target_dir}")
            raise typer.Exit(1)


        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                console.print(f"⚠️  [yellow]Config file not found: {config_path}, using defaults[/yellow]")
                config_path = None

        else:
            config_path = find_config_file(target_dir)

        config = load_config(config_path)
        config.strict = strict


        if config_path and config_path.exists():
            console.print(f"⚙️  [dim]Using config: {config_path}[/dim]")
    
        else:
            console.print("⚙️  [dim]Using default configuration[/dim]")


        analyzer = CodeAnalyzer(config)

        console.print(Panel.fit(f"🔍 [bold]Analyzing directory[/bold] [green]{target_dir}[/green]", border_style="blue"))


        all_python_files = list(target_dir.rglob("*.py"))
        if not all_python_files:
            console.print("💡 [yellow]No Python files found to analyze[/yellow]")
            return


        console.print(f"📁 [dim]Found {len(all_python_files)} Python files[/dim]")

        issues = analyzer.analyze_directory(target_dir)

        analyzed_files = set(issue.file for issue in issues)
        ignored_files = len(all_python_files) - len(analyzed_files)
        
        if ignored_files > 0:
            console.print(f"⏭️  [dim]Skipped {ignored_files} files (ignored patterns)[/dim]")

        result = AnalysisResult(issues=issues, files_analyzed=len(analyzed_files), total_issues=len(issues))


        print_analysis_result(result, output_format)


        if strict and issues:
            console.print(Panel.fit("❌ [bold red]Strict mode enabled - issues found[/bold red]", border_style="red"))
            raise typer.Exit(1)


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def branch(
    base_branch: str = typer.Argument("main", help="[bold green]Base branch[/bold green] for comparison"),
    repo_path: str = typer.Argument(".", help="[bold green]Repository path[/bold green]"),
    config_file: str = typer.Option(None, "--config", "-c", help="[yellow]Config file[/yellow] path"),
    output_format: str = typer.Option("rich", "--output", "-o", help="[blue]Output format[/blue]: rich, text, json", show_choices=True),
    strict: bool = typer.Option(False, "--strict", "-s", help="[red]Fail on warnings[/red]")
) -> None:
    """
    [bold]Analyze branch differences[/bold] compared to base branch.
    
    [dim]Examples:[/dim]
      [cyan]acr review branch main[/cyan]
      [cyan]acr review branch develop /path/to/repo[/cyan]
    """

    # TODO: Implement branch comparison logic

    console.print("⚠️ The command will be implemented in future versions. ⚠️")
    console.print("There is no need to try to use it at [bold]this time[/bold].")


@app.command()
def staged(
    repo_path: str = typer.Argument(".", help="[bold green]Repository path[/bold green]"),
    config_file: str = typer.Option(None, "--config", "-c", help="[yellow]Config file[/yellow] path"),
    output_format: str = typer.Option("rich", "--output", "-o", help="[blue]Output format[/blue]: rich, text, json",show_choices=True),
    strict: bool = typer.Option(False, "--strict", "-s", help="[red]Fail on warnings[/red]")
) -> None:
    """
    [bold]Analyze staged files[/bold] (files ready for commit).
    
    [dim]Examples:[/dim]
      [cyan]acr review staged[/cyan]
      [cyan]acr review staged /path/to/repo --strict[/cyan]
    """
    try:
        target_path = Path(repo_path)
        config_path: Optional[Path] = None


        if config_file:
            config_path = Path(config_file)
            if not config_path.exists():
                console.print(f"⚠️  [yellow]Config file not found: {config_path}, using defaults[/yellow]")
                config_path = None

        else:
            config_path = find_config_file(target_path)

        config = load_config(config_path)
        config.strict = strict


        if config_path and config_path.exists():
            console.print(f"⚙️  [dim]Using config: {config_path}[/dim]")
    
        else:
            console.print("⚙️  [dim]Using default configuration[/dim]")

        analyzer = CodeAnalyzer(config)
        git_repo = analyzer.git_repo


        console.print(
            Panel.fit(f"🔍 [bold]Analyzing staged files[/bold] in [green]{target_path}[/green]", border_style="blue")
        )

        staged_files = git_repo.get_staged_files()

        if not staged_files:
            console.print("📭 [yellow]No staged files found[/yellow]")
            return

        console.print(f"📄 [dim]Found {len(staged_files)} staged files[/dim]")


        issues = []
        for file_path in staged_files:
            if file_path.suffix == '.py':
                issues.extend(analyzer.analyze_file(file_path))


        result = AnalysisResult(issues=issues, files_analyzed=len(staged_files), total_issues=len(issues))

        print_analysis_result(result, output_format)


        if strict and issues:
            console.print(Panel.fit("❌ [bold red]Strict mode enabled - issues found[/bold red]", border_style="red"))
            raise typer.Exit(1)


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)
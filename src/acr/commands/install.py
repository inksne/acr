from __future__ import annotations

from pathlib import Path
import shutil
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from ..core.git_utils import GitHookManager, GitRepo
from .install_helpers import make_pre_commit_script, make_pre_push_script, _ensure_repo_path



app = typer.Typer(
    name="install",
    help="🔧 Installation helpers (git hooks, config)",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.command()
def hook(
    hook_type: str = typer.Argument(..., help="Hook to install: pre-commit | pre-push"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Path to repository"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing hook without prompting"),
    python_exec: Optional[str] = typer.Option(None, "--python", help="Python executable to embed in hook (default: current interpreter)"),
    hook_strict: bool = typer.Option(False, "--hook-strict/--no-hook-strict", help="Run the installed hook with --strict (fail on warnings)."),
) -> None:
    """
    Install a single git hook into the target repository.

    --force / -f - overwrite an existing hook without prompting.

    Examples:
      acr install hook pre-commit
      acr install hook pre-push --repo /path/to/repo --force
    """
    try:
        repo_path = _ensure_repo_path(repo)
        python_path = python_exec or sys.executable
        ghm = GitHookManager(repo_path=repo_path)

        if hook_type not in {"pre-commit", "pre-push"}:
            console.print(f"❌ [bold red]Unsupported hook type:[/bold red] {hook_type}")
            raise typer.Exit(1)


        script = None

        if hook_type == "pre-commit":
            script = make_pre_commit_script(python_path, hook_strict)

        else:
            script = make_pre_push_script(python_path, hook_strict)


        if ghm.hook_exists(hook_type):
            if not force:
                confirm = typer.confirm(f"Hook '{hook_type}' already exists in {repo_path}/.git/hooks. Overwrite?")
                if not confirm:
                    console.print("❗ Aborted by user — existing hook preserved.")
                    raise typer.Exit()


            hooks_dir = Path(repo_path) / ".git" / "hooks"
            hook_path = hooks_dir / hook_type
            backup_path = hook_path.with_suffix(hook_path.suffix + ".acr.bak")

            try:
                shutil.copy2(str(hook_path), str(backup_path))
                console.print(f"🔁 Existing hook backed up to: {backup_path}")

            except Exception:
                console.print("⚠️ Could not backup existing hook — continuing and will attempt to overwrite.")

        created = ghm.install_hook(hook_type, script)
        console.print(Panel.fit(f"✅ Installed hook: [green]{created}[/green]", border_style="green"))


    except ValueError as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)

    except Exception as e:
        console.print(f"❌ [bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("all")
def hook_all(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Path to repository"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing hooks without prompting"),
    python_exec: Optional[str] = typer.Option(None, "--python", help="Python executable to embed in hooks (default: current interpreter)"),
    hook_strict: bool = typer.Option(False, "--hook-strict/--no-hook-strict", help="Run the installed hook with --strict (fail on warnings)."),
) -> None:
    """
    Install both pre-commit and pre-push hooks.
    """
    try:
        repo_path = _ensure_repo_path(repo)
        python_path = python_exec or sys.executable
        ghm = GitHookManager(repo_path=repo_path)

        for hook_type in ("pre-commit", "pre-push"):
            # similar logic as in single hook
            if ghm.hook_exists(hook_type) and not force:
                confirm = typer.confirm(f"Hook '{hook_type}' exists — overwrite?")
                if not confirm:
                    console.print(f"⏭️  Skipping {hook_type}")
                    continue

                hooks_dir = Path(repo_path) / ".git" / "hooks"
                hook_path = hooks_dir / hook_type
                backup_path = hook_path.with_suffix(hook_path.suffix + ".acr.bak")

                try:
                    shutil.copy2(hook_path, backup_path)
                    console.print(f"🔁 Backed up {hook_type} to {backup_path}")

                except Exception:
                    console.print(f"⚠️ Could not backup existing {hook_type} — continuing.")


            script = None

            if hook_type == "pre-commit":
                script = make_pre_commit_script(python_path, hook_strict)

            else:
                script = make_pre_push_script(python_path, hook_strict)

            created = ghm.install_hook(hook_type, script)
            console.print(f"✅ Installed {hook_type}: {created}")

        console.print(Panel.fit("✅ Hooks installation complete", border_style="green"))


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def uninstall(
    hook_type: str = typer.Argument(..., help="Hook to uninstall: pre-commit | pre-push | all"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Path to repository"),
    restore_backup: bool = typer.Option(True, "--restore-backup/--no-restore-backup", help="Restore .acr.bak backup if present"),
) -> None:
    """
    Uninstall hook(s). If a backup (with .acr.bak suffix) exists it will optionally be restored.
    """
    try:
        repo_path = _ensure_repo_path(repo)
        hooks_dir = Path(repo_path) / ".git" / "hooks"

        targets = ("pre-commit", "pre-push") if hook_type == "all" else (hook_type,)

        for ht in targets:
            hook_path = hooks_dir / ht
            if not hook_path.exists():
                console.print(f"ℹ️  Hook not found: {hook_path}")
                continue

            try:
                hook_path.unlink()
                console.print(f"🗑️  Removed hook: {hook_path}")

            except Exception as exc:
                console.print(f"⚠️ Could not remove {hook_path}: {exc}")

            if restore_backup:
                backup = hook_path.with_suffix(hook_path.suffix + ".acr.bak")
                if backup.exists():
                    try:
                        shutil.move(str(backup), str(hook_path))
                        console.print(f"♻️  Restored backup for {ht}")

                    except Exception as exc:
                        console.print(f"⚠️ Could not restore backup {backup}: {exc}")


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def list(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Path to repository"),
) -> None:
    """
    List existing hooks in the repository and indicate whether they look like ACR-generated hooks.
    """
    try:
        repo_path = _ensure_repo_path(repo)
        hooks_dir = Path(repo_path) / ".git" / "hooks"

        if not hooks_dir.exists():
            console.print("ℹ️  No hooks directory found.")
            raise typer.Exit()

        rows = []
        for hook_file in sorted(hooks_dir.iterdir()):
            if not hook_file.is_file():
                continue

            content = hook_file.read_text(encoding="utf-8", errors="ignore")
            is_acr = "Auto-generated by ACR" in content or "acr review" in content
            rows.append((hook_file.name, "ACR" if is_acr else "other"))

        if not rows:
            console.print("ℹ️  No hook files found.")
            raise typer.Exit()


        from rich.table import Table

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Hook")
        table.add_column("Type")

        for name, t in rows:
            table.add_row(name, t)

        console.print(Panel(table, title="🔩 Git hooks"))


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def init_hooks_path(
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Path to repository"),
    dir_name: str = typer.Option("hooks", "--dir", help="Directory inside repo to store versioned hooks"),
) -> None:
    """
    Initialize a versioned hooks directory (e.g. 'hooks/') and configure git to use it via core.hooksPath.
    This allows hooks to be stored in the repository and tracked by git.
    """
    try:
        repo_path = _ensure_repo_path(repo)
        git_repo = GitRepo(repo_path)
        hooks_folder = repo_path / dir_name
        hooks_folder.mkdir(parents=True, exist_ok=True)

        # create a placeholder README so the folder is visible in repo
        readme = hooks_folder / "README.md"
        if not readme.exists():
            readme.write_text("# Repository hooks\n\nPlace hook scripts here and commit them.\n")


        try:
            git_repo.repo.git.config("core.hooksPath", dir_name)
            console.print(f"✅ Set core.hooksPath = {dir_name}")
            console.print("🔁 Now add and commit the hooks directory so it's versioned across clones.")

        except Exception as exc:
            console.print(f"⚠️ Could not set git config core.hooksPath: {exc}")


    except Exception as e:
        console.print(f"❌ [bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)
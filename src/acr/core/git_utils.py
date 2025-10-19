from pathlib import Path
from typing import Optional, Any

import git



class GitRepo:
    """Manages Git Repository operations."""

    def __init__(self, repo_path: str | Path = Path('.')) -> None:
        self.repo_path = repo_path

        try:
            self.repo = git.Repo(repo_path)

        except git.InvalidGitRepositoryError:
            raise ValueError(f"Not a valid git repository: {repo_path}")


    def get_current_branch(self) -> str:
        """Get current branch name."""
        return self.repo.active_branch.name


    def get_modified_files(self) -> list[Path]:
        """Get list of modified files in working tree."""
        modified_files = []


        for item in self.repo.index.diff(None):
            if item.a_path:
                modified_files.append(Path(item.a_path))

        for item in self.repo.index.diff('HEAD'):
            if item.a_path:
                modified_files.append(Path(item.a_path))


        return list(set(modified_files))  # Remove duplicates


    def get_staged_file_content(self, file_path: Path) -> Any:
        """
        Return file content from the index (what is staged), or None if unavailable.
        file_path may be absolute or relative; we convert it to a path relative to repo root.
        """
        try:
            repo_wd = getattr(self.repo, "working_tree_dir", None)
            base = Path(repo_wd) if repo_wd is not None else self.repo_path
            rel = Path(file_path).resolve().relative_to(base)

            return self.repo.git.show(f":{str(rel)}")

        except Exception:
            return None


    def get_staged_files(self) -> list[Path]:
        """Get files staged for commit."""

        repo_wd: Optional[str] = getattr(self.repo, "working_tree_dir", None)
        base: str | Path = Path(".")

        if isinstance(repo_wd, str):
            base = Path(repo_wd)

        else:
            base = self.repo_path

        try:
            names = self.repo.git.diff('--cached', '--name-only').splitlines()
            return [(base / n).resolve() for n in names if n]

        except git.GitCommandError:
            return [(base / Path(item.a_path)).resolve() for item in self.repo.index.diff('HEAD') if item.a_path]


    def get_unstaged_files(self) -> list[Path]:
        """Get files with unstaged changes."""
        return [Path(item.a_path) for item in self.repo.index.diff(None) if item.a_path]


    def get_untracked_files(self) -> list[Path]:
        """Get untracked files."""
        return [Path(item) for item in self.repo.untracked_files]


    def get_staged_diff_for_file(self, file_path: Path) -> Any:
        """Return diff of staged changes for a file (index vs HEAD)."""
        try:
            repo_wd = getattr(self.repo, "working_tree_dir", None)
            base = Path(repo_wd) if repo_wd is not None else self.repo_path
            rel = str(Path(file_path).resolve().relative_to(base))

            return self.repo.git.diff('--cached', '--', rel)

        except Exception:
            return ""


    def get_diff_for_file(self, file_path: Path) -> Any:
        """Get diff for specific file."""
        try:
            return self.repo.git.diff(file_path)

        except git.GitCommandError:
            return ""


    def get_file_content_at_commit(self, file_path: Path, commit_hash: str) -> Any:
        """Get file content at specific commit."""
        try:
            return self.repo.git.show(f"{commit_hash}:{file_path}")

        except git.GitCommandError:
            return None


    def is_dirty(self) -> bool:
        """Check if repository has uncommitted changes."""
        return self.repo.is_dirty()


    def get_remote_url(self) -> Optional[str]:
        """Get remote repository URL."""
        try:
            return self.repo.remotes.origin.url
        except AttributeError:
            return None



class GitHookManager:
    """Manages Git hooks installation."""

    def __init__(self, repo_path: Path = Path(".")) -> None:
        self.repo_path = repo_path

        try:
            self.repo = git.Repo(self.repo_path)

        except git.InvalidGitRepositoryError:
            raise ValueError(f"Not a git repository: {repo_path}")

        # Determine hooks directory: prefer core.hooksPath if set, otherwise default to .git/hooks
        hooks_dir: Optional[Path] = None
        try:
            # Try to read core.hooksPath from repo config
            hooks_path = self.repo.git.config("--get", "core.hooksPath")
            if hooks_path:
                candidate = Path(hooks_path)
                if not candidate.is_absolute():
                    candidate = self.repo_path / candidate

                hooks_dir = candidate.resolve()

        except Exception:
            hooks_dir = None

        if hooks_dir is None:
            hooks_dir = (self.repo_path / ".git" / "hooks").resolve()


        self.hooks_dir = hooks_dir
        self.hooks_dir.mkdir(parents=True, exist_ok=True)


    def install_hook(self, hook_type: str, hook_script: str) -> Path:
        """Install Git hook."""
        hooks_dir = self.hooks_dir
        hooks_dir.mkdir(exist_ok=True)
        
        hook_path = hooks_dir / hook_type

        if hook_path.exists():
            backup = hook_path.with_suffix(hook_path.suffix + ".bak")
            hook_path.rename(backup)

        # Create hook script with shebang and content
        script_content = "#!/bin/sh\n# Auto-generated by ACR - Automated Code Review\n" + hook_script.strip() + "\n"

        # write explicitly in UTF-8 and use Unix newlines
        with open(hook_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script_content)

        hook_path.chmod(0o755)  # Make executable

        return hook_path


    def create_pre_commit_hook(self) -> Path:
        """Create pre-commit hook for automatic code review."""

        hook_script = """
            echo "🔍 Running ACR - Automated Code Review..."
            acr review changed --strict

            if [ $? -ne 0 ]; then
                echo "❌ Code review failed. Please fix the issues before committing."
                exit 1
            fi

            echo "✅ Code review passed!"
        """

        return self.install_hook("pre-commit", hook_script)


    def create_pre_push_hook(self) -> Path:
        """Create pre-push hook for branch analysis."""

        hook_script = """
            echo "🔍 ACR: Analyzing changes before push..."
            acr review current --output json
        """

        return self.install_hook("pre-push", hook_script)


    def hook_exists(self, hook_type: str) -> bool:
        """Check if hook already exists."""

        hook_path = self.hooks_dir / hook_type
        return hook_path.exists()
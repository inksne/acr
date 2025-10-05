import ast
from pathlib import Path
from typing import Optional

from .models import CodeIssue, ReviewConfig, SeverityLevel
from .git_utils import GitRepo
from ..configuration import MAX_LINES_FUNCTION, MAX_COMPLEXITY



class CodeAnalyzer:
    """Main code analyzer class with Git support."""

    def __init__(self, config: Optional[ReviewConfig] = None) -> None:
        self.config = config or ReviewConfig()
        self.git_repo = GitRepo()


    def analyze_git_changes(self) -> list[CodeIssue]:
        """Analyze only changed files in Git repository."""
        issues = []

        modified_files = self.git_repo.get_modified_files()
        staged_files = self.git_repo.get_staged_files()
        untracked_files = self.git_repo.get_untracked_files()

        all_changed_files = set(modified_files + staged_files + untracked_files)


        for file_path in all_changed_files:
            if file_path.suffix == '.py' and not self._should_ignore(file_path):
                issues.extend(self.analyze_file(file_path))

        return issues



    def analyze_branch_diff(self, base_branch: str = "main") -> list[CodeIssue]:
        """Analyze differences between current branch and base branch."""
        issues: list[CodeIssue] = []

        current_branch = self.git_repo.get_current_branch()
        if current_branch == base_branch:
            return issues

        # TODO: Implement branch comparison logic

        return issues


    def analyze_file(self, file_path: Path) -> list[CodeIssue]:
        """Analyze single Python file."""
        issues = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            file_diff = self.git_repo.get_diff_for_file(file_path)
            tree = ast.parse(content, filename=str(file_path))


            issues.extend(self._check_magic_numbers(tree, file_path))
            issues.extend(self._check_long_functions(tree, file_path))
            issues.extend(self._check_unused_imports(tree, file_path))
            issues.extend(self._check_complex_functions(tree, file_path))
            issues.extend(self._check_undefined_variables(tree, file_path))
            issues.extend(self._check_unused_variables(tree, file_path))


            # Add Git context to issues
            for issue in issues:
                issue.suggestion = self._get_git_aware_suggestion(issue, file_diff)


        except (SyntaxError, UnicodeDecodeError) as e:
            issues.append(CodeIssue(
                file=file_path,
                line=1,
                message=f"❌ [bold red]Could not parse file:[/bold red] {e}.",
                severity=SeverityLevel.ERROR
            ))

        return issues


    def _check_magic_numbers(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for magic numbers in code using AST."""
        issues: list[CodeIssue] = []
        magic_number_rule = self.config.rules.get("magic_number")

        if not magic_number_rule or not magic_number_rule.enabled:
            return issues


        ignored_numbers = {0, 1, -1, 100, 1000}

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                number = node.value

                if number in ignored_numbers:
                    continue

                issues.append(CodeIssue(
                    file=file_path,
                    line=node.lineno,
                    message=f"❌ [bold yellow]Magic number found:[/bold yellow] [bold]{number}[/bold].",
                    severity=magic_number_rule.severity,
                    rule_id="magic_number",
                    suggestion="[italic]Consider defining this as a named constant.[/italic]"
                ))

        return issues


    def _check_long_functions(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for functions that are too long."""
        issues: list[CodeIssue] = []
        long_function_rule = self.config.rules.get("long_function")

        if not long_function_rule or not long_function_rule.enabled:
            return issues

        max_lines = long_function_rule.parameters.get("max_lines", MAX_LINES_FUNCTION)


        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = node.lineno
                end_line = getattr(node, 'end_lineno', start_line)
                function_length = end_line - start_line + 1


                if function_length > max_lines:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ Function [bold magenta]'{node.name}'[/bold magenta] is [bold yellow]too long[/bold yellow] ([bold]{function_length}[/bold] lines).",
                        severity=long_function_rule.severity,
                        rule_id="long_function",
                        suggestion=f"[italic]Consider breaking this function into smaller functions (max [bold]{max_lines}[/bold] lines).[/italic]"
                    ))

        return issues


    def _check_unused_imports(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for unused imports."""
        issues: list[CodeIssue] = []
        unused_import_rule = self.config.rules.get("unused_import")

        if not unused_import_rule or not unused_import_rule.enabled:
            return issues


        imports: dict[str, tuple[int, str, str]] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    actual_name = alias.asname or alias.name
                    imports[actual_name] = (node.lineno, alias.name, alias.asname or "")


        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_names.add(node.id)


        for imported_name, (line, original_name, alias) in imports.items():
            if imported_name not in used_names:
                if alias:
                    display_name = f"{original_name} (as {alias})"

                else:
                    display_name = original_name

                issues.append(CodeIssue(
                    file=file_path,
                    line=line,
                    message=f"❌ [bold yellow]Unused import:[/bold yellow] [bold magenta]{display_name}[/bold magenta]",
                    severity=unused_import_rule.severity,
                    rule_id="unused_import",
                    suggestion="[italic]Remove this unused import to clean up namespace.[/italic]"
                ))


        return issues


    def _collect_defined_names(self, tree: ast.AST) -> set[str]:
        """Collect all defined names (variables, functions, imports, etc.)."""
        defined_names = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    defined_names.add(alias.asname or alias.name)

            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    defined_names.add(alias.asname or alias.name)

            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_names.add(target.id)

            elif isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                defined_names.add(node.name)

            elif isinstance(node, ast.arguments):
                for arg in node.args:
                    defined_names.add(arg.arg)

                if node.vararg:
                    defined_names.add(node.vararg.arg)

                if node.kwarg:
                    defined_names.add(node.kwarg.arg)

        return defined_names


    def _collect_used_names(self, tree: ast.AST) -> list[tuple[str, int]]:
        """Collect all used variable names with their line numbers."""
        used_names = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                # Eliminate special names and methods dunder
                if not node.id.startswith('_') or (node.id.startswith('__') and node.id.endswith('__')):
                    used_names.append((node.id, node.lineno))

        return used_names


    def _is_builtin(self, name: str) -> bool:
        """Check if name is a Python builtin."""
        import builtins
        return hasattr(builtins, name)


    def _check_undefined_variables(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for undefined variables using AST analysis."""
        issues: list[CodeIssue] = []
        undefined_rule = self.config.rules.get("undefined_variable")

        if not undefined_rule or not undefined_rule.enabled:
            return issues


        defined_names = self._collect_defined_names(tree)

        used_names = self._collect_used_names(tree)

        for name, line in used_names:
            if name not in defined_names and not self._is_builtin(name):
                issues.append(CodeIssue(
                    file=file_path,
                    line=line,
                    message=f"❌ [bold red]Undefined variable:[/bold red] [bold]{name}[/bold]",
                    severity=undefined_rule.severity,
                    rule_id="undefined_variable",
                    suggestion="[italic]Define this variable or check for typos.[/italic]"
                ))

        return issues


    def _collect_used_variables(self, tree: ast.AST) -> set[str]:
        """Collect all variable names that are used (read from)."""
        used_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                # Exclude built-in functions and special names
                if not self._is_builtin(node.id) and not node.id.startswith('__'):
                    used_vars.add(node.id)

        return used_vars


    def _process_function_arguments(self, func_node: ast.AST, defined_vars: dict[str, tuple[int, str]]) -> None:
        """Process function arguments and add them to defined_vars."""
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        args = func_node.args
        lineno = func_node.lineno


        for arg in args.args:
            defined_vars[arg.arg] = (lineno, "function parameter")

        # *args
        if args.vararg:
            defined_vars[args.vararg.arg] = (lineno, "*args parameter")

        # **kwargs
        if args.kwarg:
            defined_vars[args.kwarg.arg] = (lineno, "**kwargs parameter")

        # keyword-only
        for kwarg in args.kwonlyargs:
            defined_vars[kwarg.arg] = (lineno, "keyword-only parameter")


    def _collect_defined_variables(self, tree: ast.AST) -> dict[str, tuple[int, str]]:
        """Collect all variable definitions with their line numbers and types."""
        defined_vars: dict[str, tuple[int, str]] = {}
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_vars[target.id] = (target.lineno, "variable")

            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                defined_vars[node.target.id] = (node.target.lineno, "typed variable")

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._process_function_arguments(node, defined_vars)

        return defined_vars


    def _should_ignore_variable(self, var_name: str, var_type: str) -> bool:
        """Determine if a variable should be ignored from unused checks."""
        if var_name.startswith('_'):
            if var_name.startswith('__') and var_name.endswith('__'):
                return True

            if var_type in ["variable", "typed variable"]:
                return True

            if var_type not in ["function parameter", "*args parameter", "**kwargs parameter", "keyword-only parameter"]:
                return True

        ignored_names = {
            'self', 'cls',
            'mcs',  # meta classes
            'args', 'kwargs',
            'config', 'settings',  # config variables
        }

        return var_name in ignored_names


    def _check_unused_variables(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for variables that are defined but not used."""
        issues: list[CodeIssue] = []
        unused_rule = self.config.rules.get("unused_variable")
        
        if not unused_rule or not unused_rule.enabled:
            return issues

        used_variables = self._collect_used_variables(tree)

        defined_variables = self._collect_defined_variables(tree)

        for var_name, (line, var_type) in defined_variables.items():
            if var_name not in used_variables and not self._should_ignore_variable(var_name, var_type):
                issues.append(CodeIssue(
                    file=file_path,
                    line=line,
                    message=f"❌ [bold yellow]Unused variable:[/bold yellow] [bold]{var_name}[/bold] ({var_type})",
                    severity=unused_rule.severity,
                    rule_id="unused_variable",
                    suggestion="[italic]Remove this unused variable to clean up the namespace.[/italic]"
                ))

        return issues


    def _check_complex_functions(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for functions with high complexity."""
        issues = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._calculate_complexity(node)
                
                if complexity > MAX_COMPLEXITY:  # McCabe complexity threshold
                    issues.append(CodeIssue(
                        file=file_path,
                        line=node.lineno,
                        message=f"❌ Function [bold magenta]'{node.name}'[/bold magenta] is [bold yellow]too complex[/bold yellow] (complexity: [bold]{complexity}[/bold]).",
                        severity=SeverityLevel.WARNING,
                        rule_id="high_complexity",
                        suggestion="[italic]Consider refactoring to reduce complexity (extract methods, simplify conditions).[/italic]"
                    ))

        return issues


    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate McCabe complexity for a function."""
        complexity = 1  # Start with 1 for the function itself

        for child in ast.walk(node):
            if isinstance(child, (
                ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try, ast.ExceptHandler, ast.With, ast.AsyncWith
            )):
                complexity += 1

            elif isinstance(child, (ast.BoolOp, ast.Compare)):
                complexity += 1

        return complexity


    def _get_git_aware_suggestion(self, issue: CodeIssue, file_diff: str) -> str:
        """Generate context-aware suggestions based on Git diff."""

        has_changes = bool(file_diff.strip())

        if "magic number" in issue.message.lower():
            if has_changes:
                return "[green]🔧 Consider extracting this magic number to a named constant [bold]before committing[/bold].[/green]"

            else:
                return "[green]💡 Consider extracting this magic number to a named constant during refactoring.[/green]"

        elif "too long" in issue.message.lower():
            if has_changes:
                return "[green]🔧 This might be a good candidate for refactoring [bold]before committing[/bold].[/green]"

            else:
                return "[green]💡 Consider breaking this function into smaller pieces during code review.[/green]"

        elif "unused import" in issue.message.lower():
            if has_changes:
                return "[green]🧹 Clean up this unused import [bold]before committing[/bold] to improve code clarity.[/green]"

            else:
                return "[green]💡 Remove this unused import to clean up the namespace.[/green]"

        elif "unused variable" in issue.message.lower():
            if has_changes:
                return "[green]🧹 Remove this unused variable [bold]before committing[/bold] to clean up the namespace.[/green]"

            else:
                return "[green]💡 This variable is not used - consider removing it during code cleanup.[/green]"

        elif "undefined variable" in issue.message.lower():
            if has_changes:
                return "[green]🔧 Define this variable or fix the typo [bold]before committing[/bold].[/green]"

            else:
                return "[green]💡 This variable is not defined - check for typos or missing imports.[/green]"

        elif "too complex" in issue.message.lower():
            if has_changes:
                return "[green]🔧 This function is complex - consider simplifying [bold]before committing[/bold].[/green]"

            else:
                return "[green]💡 This function has high complexity - good candidate for future refactoring.[/green]"

        if has_changes:
            return "[blue]📝 Review this code [bold]before committing[/bold] to ensure quality.[/blue]"

        else:
            return "[blue]👀 This code could benefit from review and improvement.[/blue]"


    def _should_ignore(self, file_path: Path) -> bool:
        """Check if file should be ignored based on patterns."""
        file_path_str = str(file_path)

        for pattern in self.config.ignore_patterns:
            if Path(file_path_str).match(pattern):
                return True

        for exclude_path in self.config.exclude_paths:
            if exclude_path in file_path_str:
                return True

        return False


    def analyze_directory(self, directory_path: Path) -> list[CodeIssue]:
        """Analyze all Python files in a directory."""
        issues = []

        for py_file in directory_path.rglob("*.py"):
            if not self._should_ignore(py_file):
                issues.extend(self.analyze_file(py_file))

        return issues
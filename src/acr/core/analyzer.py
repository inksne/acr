import ast
from pathlib import Path
from typing import Optional

from .models import CodeIssue, ReviewConfig, SeverityLevel
from .git_utils import GitRepo
from ..configuration import MAX_LINES_FUNCTION, MAX_COMPLEXITY, MAX_LINE_LENGTH_PEP8, MAX_BLANK_LINES


class CodeAnalyzer:
    """Main code analyzer class with Git support."""

    def __init__(self, config: Optional[ReviewConfig] = None) -> None:
        self.config = config or ReviewConfig()
        self.git_repo = GitRepo()

    # ==================== PUBLIC INTERFACE ====================

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
            issues.extend(self._check_type_annotations(tree, file_path))
            issues.extend(self._check_pep8(tree, file_path))
            issues.extend(self._check_inline_comments(file_path))

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


    def analyze_directory(self, directory_path: Path) -> list[CodeIssue]:
        """Analyze all Python files in a directory."""
        issues = []

        for py_file in directory_path.rglob("*.py"):
            if not self._should_ignore(py_file):
                issues.extend(self.analyze_file(py_file))

        return issues

    # ==================== CORE ANALYSIS METHODS ====================

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
                for alias_node in node.names:
                    actual_name = alias_node.asname or alias_node.name
                    imports[actual_name] = (node.lineno, alias_node.name, alias_node.asname or "")


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


    def _check_complex_functions(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for functions with high complexity."""
        issues: list[CodeIssue] = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._calculate_complexity(node)
                
                if complexity > MAX_COMPLEXITY:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=node.lineno,
                        message=f"❌ Function [bold magenta]'{node.name}'[/bold magenta] is [bold yellow]too complex[/bold yellow] (complexity: [bold]{complexity}[/bold]).",
                        severity=SeverityLevel.WARNING,
                        rule_id="high_complexity",
                        suggestion="[italic]Consider refactoring to reduce complexity (extract methods, simplify conditions).[/italic]"
                    ))

        return issues


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


    def _check_type_annotations(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for missing and incorrect type annotations."""
        issues: list[CodeIssue] = []
        issues.extend(self._check_missing_type_annotations(tree, file_path))
        issues.extend(self._check_incorrect_type_annotations(tree, file_path))
        return issues


    def _check_pep8(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for PEP 8 style guide violations."""
        issues: list[CodeIssue] = []
        pep8_rule = self.config.rules.get("pep8")
        
        if not pep8_rule or not pep8_rule.enabled:
            return issues

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

        except Exception:
            return issues


        issues.extend(self._check_line_length(lines, file_path))
        issues.extend(self._check_blank_lines(lines, file_path))
        issues.extend(self._check_import_order(tree, file_path))
        issues.extend(self._check_naming_conventions(tree, file_path))
        issues.extend(self._check_whitespace(tree))
        issues.extend(self._check_trailing_whitespace(lines, file_path))


        return issues

    # ==================== TYPE ANNOTATION CHECKS ====================

    def _check_missing_type_annotations(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for missing type annotations in functions and methods."""
        issues: list[CodeIssue] = []
        missing_annotation_rule = self.config.rules.get("missing_type_annotation")
        
        if not missing_annotation_rule or not missing_annotation_rule.enabled:
            return issues

        type_annotations = self._collect_type_annotations(tree)


        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                issues.extend(self._check_function_annotations(node, file_path))

            elif isinstance(node, ast.Assign) and self._is_top_level(node):
                issues.extend(self._check_variable_annotations(node, file_path, type_annotations))

        return issues


    def _check_incorrect_type_annotations(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check for potentially incorrect type annotations."""
        issues: list[CodeIssue] = []
        incorrect_annotation_rule = self.config.rules.get("incorrect_type_annotation")
        type_mismatch_rule = self.config.rules.get("type_mismatch")

        if (not incorrect_annotation_rule or not incorrect_annotation_rule.enabled) and \
           (not type_mismatch_rule or not type_mismatch_rule.enabled):
            return issues

        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and node.annotation:
                issues.extend(self._check_single_annotation(node, file_path))
                if type_mismatch_rule and type_mismatch_rule.enabled and node.value:
                    issues.extend(self._check_type_mismatch(node, file_path))

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.annotation:
                        issues.extend(self._check_single_annotation(arg, file_path, is_argument=True))

                if node.returns:
                    issues.extend(self._check_single_annotation(node, file_path, is_return=True))
                    if type_mismatch_rule and type_mismatch_rule.enabled:
                        issues.extend(self._check_return_type_mismatch(node, file_path))

        return issues


    def _check_function_annotations(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> list[CodeIssue]:
        """Check type annotations for a function."""
        issues: list[CodeIssue] = []

        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return issues


        for arg in func_node.args.args:
            if not arg.annotation:
                issues.append(CodeIssue(
                    file=file_path,
                    line=arg.lineno,
                    message=f"❌ [bold yellow]Missing type annotation for parameter:[/bold yellow] [bold]{arg.arg}[/bold]",
                    severity=SeverityLevel.INFO,
                    rule_id="missing_type_annotation",
                    suggestion="[italic]Add type annotation to improve code clarity and enable static checking.[/italic]"
                ))


        if not func_node.returns:
            issues.append(CodeIssue(
                file=file_path,
                line=func_node.lineno,
                message=f"❌ [bold yellow]Missing return type annotation for function:[/bold yellow] [bold]{func_node.name}[/bold]",
                severity=SeverityLevel.INFO,
                rule_id="missing_type_annotation",
                suggestion="[italic]Add return type annotation to document function behavior.[/italic]"
            ))

        return issues


    def _check_variable_annotations(
        self,
        assign_node: ast.Assign,
        file_path: Path,
        type_annotations: dict[str, ast.AnnAssign]
    ) -> list[CodeIssue]:
        """Check for missing type annotations in module-level variables."""
        issues: list[CodeIssue] = []

        for target in assign_node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                if self._should_ignore_variable_name(var_name):
                    continue

                if var_name not in type_annotations:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=target.lineno,
                        message=f"❌ [bold yellow]Missing type annotation for variable:[/bold yellow] [bold]{var_name}[/bold]",
                        severity=SeverityLevel.INFO,
                        rule_id="missing_type_annotation",
                        suggestion="[italic]Consider adding type annotation for important module-level variables.[/italic]"
                    ))

        return issues


    def _check_single_annotation(
        self,
        node: ast.AST,
        file_path: Path,
        is_argument: bool = False,
        is_return: bool = False
    ) -> list[CodeIssue]:
        """Check a single type annotation for potential issues."""
        issues: list[CodeIssue] = []
        
        if is_return:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotation_node = node.returns
                context = f"return type of '{node.name}'"

            else:
                return issues

        elif is_argument and isinstance(node, ast.arg):
            annotation_node = node.annotation
            context = f"parameter '{node.arg}'"

        elif isinstance(node, ast.AnnAssign):
            annotation_node = node.annotation
            target_name = node.target.id if isinstance(node.target, ast.Name) else "variable"
            context = f"variable '{target_name}'"

        else:
            return issues


        if not annotation_node:
            return issues


        if self._is_any_annotation(annotation_node):
            issues.append(CodeIssue(
                file=file_path,
                line=annotation_node.lineno,
                message=f"❌ [bold yellow]Use of 'Any' type for {context}[/bold yellow]",
                severity=SeverityLevel.INFO,
                rule_id="incorrect_type_annotation",
                suggestion="[italic]Avoid using 'Any' when possible. Use more specific types for better type safety.[/italic]"
            ))


        if self._is_object_annotation(annotation_node):
            issues.append(CodeIssue(
                file=file_path,
                line=annotation_node.lineno,
                message=f"❌ [bold yellow]Use of generic 'object' type for {context}[/bold yellow]",
                severity=SeverityLevel.INFO,
                rule_id="incorrect_type_annotation", 
                suggestion="[italic]Consider using more specific types instead of generic 'object'.[/italic]"
            ))

        return issues


    def _check_type_mismatch(self, ann_assign_node: ast.AnnAssign, file_path: Path) -> list[CodeIssue]:
        """Check if annotated type matches the assigned value."""
        issues: list[CodeIssue] = []

        if not isinstance(ann_assign_node.target, ast.Name):
            return issues

        var_name = ann_assign_node.target.id
        annotation_type = self._annotation_to_string(ann_assign_node.annotation)
        value_type = self._value_to_type_string(ann_assign_node.value)

        if value_type and annotation_type and not self._types_are_compatible(annotation_type, value_type):
            issues.append(CodeIssue(
                file=file_path,
                line=ann_assign_node.lineno,
                message=f"❌ [bold yellow]Type mismatch:[/bold yellow] [bold]{var_name}[/bold] is annotated as [yellow]{annotation_type}[/yellow] but assigned [red]{value_type}[/red]",
                severity=SeverityLevel.INFO,
                rule_id="type_mismatch",
                suggestion="[italic]Fix the type annotation or the assigned value to resolve the type conflict.[/italic]"
            ))

        return issues


    def _check_return_type_mismatch(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> list[CodeIssue]:
        """Check if function return type matches the actual returned values."""
        issues: list[CodeIssue] = []

        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not func_node.returns:
            return issues

        return_annotation = self._annotation_to_string(func_node.returns)
        return_types = self._get_function_return_types(func_node)

        for return_type in return_types:
            if return_type and return_annotation and not self._types_are_compatible(return_annotation, return_type):
                issues.append(CodeIssue(
                    file=file_path,
                    line=func_node.lineno,
                    message=f"❌ [bold yellow]Return type mismatch:[/bold yellow] Function [bold]{func_node.name}[/bold] returns [red]{return_type}[/red] but annotated as [yellow]{return_annotation}[/yellow]",
                    severity=SeverityLevel.INFO,
                    rule_id="type_mismatch",
                    suggestion="[italic]Fix the return type annotation or the returned values to resolve the type conflict.[/italic]"
                ))
                break  # One error per function is enough

        return issues

    # ==================== PEP 8 CHECKS ====================

    def _check_line_length(self, lines: list[str], file_path: Path) -> list[CodeIssue]:
        """Check if lines exceed maximum length (PEP 8: 79 characters)."""
        issues: list[CodeIssue] = []

        for i, line in enumerate(lines, 1):
            line_no_newline = line.rstrip('\r\n')
            if len(line_no_newline) > MAX_LINE_LENGTH_PEP8:
                if not any(x in line_no_newline for x in ['http://', 'https://', 'pragma:', 'type:']):
                    issues.append(CodeIssue(
                        file=file_path,
                        line=i,
                        message=f"❌ [bold yellow]Line too long ({len(line_no_newline)} > {MAX_LINE_LENGTH_PEP8} characters)[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Break long lines to improve readability.[/italic]"
                    ))

        return issues


    def _check_blank_lines(self, lines: list[str], file_path: Path) -> list[CodeIssue]:
        """Check for proper blank line usage (PEP 8)."""
        issues: list[CodeIssue] = []
        blank_line_count = 0

        for i, line in enumerate(lines, 1):
            stripped_line = line.rstrip()
            if not stripped_line:
                blank_line_count += 1
                if blank_line_count > MAX_BLANK_LINES:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=i,
                        message="❌ [bold yellow]Too many blank lines[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Use maximum 2 blank lines between top-level definitions.[/italic]"
                    ))

            else:
                blank_line_count = 0


        return issues


    def _check_import_order(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check import order (PEP 8: stdlib, third-party, local)."""
        issues: list[CodeIssue] = []
        imports: list[tuple[int, str, str]] = []  # (line, module, type)

        stdlib_modules = {'sys', 'os', 'json', 'datetime', 'collections', 'pathlib', 'typing'}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((node.lineno, alias.name, "import"))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append((node.lineno, node.module, "from"))

        stdlib_imports = []
        third_party_imports = []
        local_imports = []

        for lineno, module, import_type in imports:
            if any(module.startswith(stdlib) for stdlib in stdlib_modules) or module in stdlib_modules:
                stdlib_imports.append((lineno, module, import_type))

            elif '.' in module and not module.startswith('.'):
                third_party_imports.append((lineno, module, import_type))

            else:
                local_imports.append((lineno, module, import_type))

        current_section = "stdlib"
        
        for lineno, module, import_type in imports:
            if module in [m for _, m, _ in stdlib_imports]:
                if current_section != "stdlib":
                    issues.append(CodeIssue(
                        file=file_path,
                        line=lineno,
                        message=f"❌ [bold yellow]Import order violation: {module}[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Standard library imports should come first, then third-party, then local imports.[/italic]"
                    ))

                current_section = "stdlib"

            elif module in [m for _, m, _ in third_party_imports]:
                if current_section == "local":
                    issues.append(CodeIssue(
                        file=file_path,
                        line=lineno,
                        message=f"❌ [bold yellow]Import order violation: {module}[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Third-party imports should come after standard library imports.[/italic]"
                    ))

                current_section = "third_party"

            else:
                current_section = "local"


        return issues


    def _check_naming_conventions(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Check naming conventions (PEP 8)."""
        issues: list[CodeIssue] = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if not self._is_camel_case(node.name):
                    issues.append(CodeIssue(
                        file=file_path,
                        line=node.lineno,
                        message=f"❌ [bold yellow]Class name should be in CamelCase: {node.name}[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Use CamelCase for class names (e.g., MyClass).[/italic]"
                    ))


            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not self._is_snake_case(node.name):
                    issues.append(CodeIssue(
                        file=file_path,
                        line=node.lineno,
                        message=f"❌ [bold yellow]Function name should be in snake_case: {node.name}[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Use snake_case for function and variable names (e.g., my_function).[/italic]"
                    ))


            elif isinstance(node, ast.Assign):
                if (len(node.targets) == 1 and 
                    isinstance(node.targets[0], ast.Name) and
                    self._is_constant_name(node.targets[0].id)):
                    
                    if not node.targets[0].id.isupper():
                        issues.append(CodeIssue(
                            file=file_path,
                            line=node.lineno,
                            message=f"❌ [bold yellow]Constant should be in UPPER_CASE: {node.targets[0].id}[/bold yellow]",
                            severity=SeverityLevel.INFO,
                            rule_id="pep8",
                            suggestion="[italic]Use UPPER_CASE for constants (e.g., MAX_VALUE).[/italic]"
                        ))

        return issues


    def _check_whitespace(self, tree: ast.AST) -> list[CodeIssue]:
        """Check for proper whitespace usage (PEP 8)."""
        issues: list[CodeIssue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp):
                pass


            if isinstance(node, ast.Call):
                if node.args and len(node.args) > 1:
                    pass

        return issues


    def _check_trailing_whitespace(self, lines: list[str], file_path: Path) -> list[CodeIssue]:
        """Check for trailing whitespace (spaces or tabs before newline)."""
        issues: list[CodeIssue] = []

        for i, line in enumerate(lines, 1):
            line_no_newline = line.rstrip('\r\n')

            # if a string without a newline is different from a string without a newline and without spaces,
            # means there are spaces/tabs at the end (i.e. trailing whitespaces)

            if line_no_newline != line_no_newline.rstrip(' \t'):
                issues.append(CodeIssue(
                    file=file_path,
                    line=i,
                    message="❌ [bold yellow]Trailing whitespace[/bold yellow]",
                    severity=SeverityLevel.INFO,
                    rule_id="pep8",
                    suggestion="[italic]Remove trailing whitespace.[/italic]"
                ))

        return issues


    def _is_snake_case(self, name: str) -> bool:
        """Check if name is in snake_case."""
        if not name:
            return False

        if name.startswith('__') and name.endswith('__'):
            return True

        if name.startswith('_'):
            name = name[1:]

        return all(c.islower() or c.isdigit() or c == '_' for c in name)


    def _is_camel_case(self, name: str) -> bool:
        """Check if name is in CamelCase."""
        if not name:
            return False

        if name.startswith('_'):
            name = name[1:]

        return name[0].isupper() and '_' not in name

    def _is_constant_name(self, name: str) -> bool:
        """Check if variable name suggests it should be a constant."""
        constant_indicators = {'MAX', 'MIN', 'DEFAULT', 'CONFIG', 'SETTINGS', 'CONSTANT'}

        return any(indicator in name.upper() for indicator in constant_indicators)


    def _check_inline_comments(self, file_path: Path) -> list[CodeIssue]:
        """
        Check for inline comments (comment on same line as code).
        Allow comments that contain allowed markers like `type: ignore`, `noqa`, `pragma`, etc.
        Uses the tokenize module to avoid false-positives for '#' inside strings.
        """
        issues: list[CodeIssue] = []
        pep8_rule = self.config.rules.get("pep8")
        if not pep8_rule or not pep8_rule.enabled:
            return issues

        allowed_markers = [
            "type: ignore", "noqa", "pragma", "pylint:", "flake8", "coverage: ignore",
            "no-cover", "nocover", "no cover", "nolint"
        ]

        try:
            import tokenize

            with open(file_path, "rb") as f:
                tokens = tokenize.tokenize(f.readline)
                # For each line we mark whether there was a piece of code before the comment

                code_seen_on_line: dict[int, bool] = {}

                for tok in tokens:
                    tok_type = tok.type
                    tok_string = tok.string
                    lineno = tok.start[0]

                    if tok_type == tokenize.COMMENT:
                        comment_text = tok_string.lstrip('#').strip().lower()

                        if any(marker in comment_text for marker in allowed_markers):
                            continue

                        if code_seen_on_line.get(lineno, False):
                            issues.append(CodeIssue(
                                file=file_path,
                                line=lineno,
                                message="❌ [bold yellow]Inline comment on code line[/bold yellow]",
                                severity=pep8_rule.severity,
                                rule_id="pep8",
                                suggestion="[italic]Move the comment to a separate line above the code or use an allowed inline marker (e.g. `# type: ignore`).[/italic]"
                            ))

                    else:
                        # consider tokens other than NL/NEWLINE/ENCODING/ENDMARKER/INDENT/DEDENT/COMMENT to be “code”
                        if tok_type not in (
                            tokenize.NL, tokenize.NEWLINE, tokenize.ENCODING,
                            tokenize.ENDMARKER, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT
                        ):

                            code_seen_on_line[lineno] = True


        except Exception:
            return issues

        return issues

    # ==================== HELPER METHODS (USED BY OTHERS) ====================

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


    def _collect_used_variables(self, tree: ast.AST) -> set[str]:
        """Collect all variable names that are used (read from)."""
        used_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                # Exclude built-in functions and special names
                if not self._is_builtin(node.id) and not node.id.startswith('__'):
                    used_vars.add(node.id)

        return used_vars


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


    def _collect_type_annotations(self, tree: ast.AST) -> dict[str, ast.AnnAssign]:
        """Collect all type annotations from the module."""
        annotations = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                annotations[node.target.id] = node

        return annotations

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

    # ==================== UTILITY METHODS ====================

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a Python builtin."""
        import builtins
        return hasattr(builtins, name)


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
            'self', 'cls', 'mcs', 'args', 'kwargs', 'config', 'settings'
        }

        return var_name in ignored_names


    def _should_ignore_variable_name(self, var_name: str) -> bool:
        """Check if variable name should be ignored for type annotation checks."""
        if var_name.startswith('_'):
            return True

        ignored_names = {
            '__name__', '__file__', '__doc__', '__package__',
            '__version__', '__author__', '__all__'
        }

        return var_name in ignored_names


    def _is_top_level(self, node: ast.AST) -> bool:
        """Check if node is at module level (not inside function/class)."""
        current = node
        while hasattr(current, 'parent'):
            current = current.parent
            if isinstance(current, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                return False

        return True


    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate McCabe complexity for a function."""
        complexity = 1  # Start with 1 for the function itself

        for child in ast.walk(node):
            if isinstance(child, (
                ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try, 
                ast.ExceptHandler, ast.With, ast.AsyncWith
            )):
                complexity += 1

            elif isinstance(child, (ast.BoolOp, ast.Compare)):
                complexity += 1

        return complexity


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

    # ==================== TYPE ANNOTATION UTILITIES ====================

    def _annotation_to_string(self, annotation_node: ast.AST) -> str:
        """Convert annotation AST node to string representation."""
        if annotation_node is None:
            return "unknown"

        if isinstance(annotation_node, ast.Name):
            return getattr(annotation_node, 'id', 'unknown')

        elif isinstance(annotation_node, ast.Attribute):
            value = getattr(annotation_node, 'value', None)
            attr = getattr(annotation_node, 'attr', 'unknown')

            if value is not None:
                value_str = self._annotation_to_string(value)
                return f"{value_str}.{attr}"

            return attr

        elif isinstance(annotation_node, ast.Subscript):
            value = getattr(annotation_node, 'value', None)

            if value is not None:
                base = self._annotation_to_string(value)
                return f"{base}[...]"

            return "unknown"

        elif isinstance(annotation_node, ast.Constant):
            value = getattr(annotation_node, 'value', None)
            if isinstance(value, str):
                return value

        return "unknown"


    def _value_to_type_string(self, value_node: Optional[ast.AST]) -> str:
        """Determine type string from value AST node."""
        if value_node is None:
            return "unknown"


        if isinstance(value_node, ast.Constant):
            if value_node.value is None:
                return "None"

            elif isinstance(value_node.value, str):
                return "str"

            elif isinstance(value_node.value, int):
                return "int"

            elif isinstance(value_node.value, float):
                return "float"

            elif isinstance(value_node.value, bool):
                return "bool"

            elif isinstance(value_node.value, bytes):
                return "bytes"


        elif isinstance(value_node, ast.List) or isinstance(value_node, ast.ListComp):
            return "list"

        elif isinstance(value_node, ast.Dict) or isinstance(value_node, ast.DictComp):
            return "dict"

        elif isinstance(value_node, ast.Set) or isinstance(value_node, ast.SetComp):
            return "set"

        elif isinstance(value_node, ast.Tuple):
            return "tuple"

        elif isinstance(value_node, ast.Call):
            if isinstance(value_node.func, ast.Name):
                return value_node.func.id

            elif isinstance(value_node.func, ast.Attribute):
                return value_node.func.attr

        return "unknown"


    def _get_function_return_types(self, func_node: ast.AST) -> set[str]:
        """Get the types of values returned by a function."""
        return_types = set()
        
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return_types.add(self._value_to_type_string(node.value))

        return return_types


    def _types_are_compatible(self, annotated_type: str, actual_type: str) -> bool:
        """Check if types are compatible (simplified check)."""
        compatibility_map = {
            "str": {"str"},
            "int": {"int", "float"},
            "float": {"float", "int"},
            "bool": {"bool"},
            "list": {"list"},
            "dict": {"dict"},
            "set": {"set"},
            "tuple": {"tuple"},
            "None": {"None"},
        }

        if annotated_type == actual_type:
            return True

        compatible_types = compatibility_map.get(annotated_type, set())
        return actual_type in compatible_types


    def _is_any_annotation(self, annotation_node: ast.AST) -> bool:
        """Check if annotation is typing.Any."""
        if isinstance(annotation_node, ast.Name) and annotation_node.id == 'Any':
            return True

        elif (isinstance(annotation_node, ast.Attribute) and 
            isinstance(annotation_node.value, ast.Name) and
            annotation_node.value.id == 'typing' and
            annotation_node.attr == 'Any'):

            return True

        return False


    def _is_object_annotation(self, annotation_node: ast.AST) -> bool:
        """Check if annotation is plain object."""
        return (isinstance(annotation_node, ast.Name) and annotation_node.id == 'object')


    def _is_string_annotation(self, annotation_node: ast.AST) -> bool:
        """Check if annotation is a string (forward reference)."""
        return isinstance(annotation_node, ast.Constant) and isinstance(annotation_node.value, str)

    # ==================== OUTPUT FORMATTING ====================

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

        elif "missing type annotation" in issue.message.lower():
            if has_changes:
                return "[green]📝 Add type annotation [bold]before committing[/bold] to improve code documentation.[/green]"

            else:
                return "[green]💡 Add type annotation to improve code clarity and enable better static analysis.[/green]"

        elif "use of 'any' type" in issue.message.lower():
            if has_changes:
                return "[green]🔧 Replace 'Any' with specific type [bold]before committing[/bold] for better type safety.[/green]"

            else:
                return "[green]💡 Consider replacing 'Any' with more specific types where possible.[/green]"

        elif "use of generic 'object' type" in issue.message.lower():
            if has_changes:
                return "[green]🔧 Use more specific type instead of 'object' [bold]before committing[/bold].[/green]"

            else:
                return "[green]💡 Generic 'object' type provides little type information - consider more specific types.[/green]"

        elif "type mismatch" in issue.message.lower():
            if has_changes:
                return "[green]🔧 Fix type annotation or value [bold]before committing[/bold] to resolve type conflict.[/green]"

            else:
                return "[green]💡 The type annotation doesn't match the actual value - fix this type conflict.[/green]"

        elif issue.rule_id and "pep8" in issue.rule_id:
            if "line too long" in issue.message.lower():
                if has_changes:
                    return "[green]📏 Break long line [bold]before committing[/bold] to improve readability.[/green]"

                else:
                    return "[green]💡 Break long lines to comply with PEP 8 (79 characters).[/green]"

            elif "blank lines" in issue.message.lower():
                if has_changes:
                    return "[green]📝 Fix blank lines [bold]before committing[/bold] to follow PEP 8.[/green]"

                else:
                    return "[green]💡 Use proper blank line spacing (max 2 lines between top-level definitions).[/green]"

            elif "import order" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Reorder imports [bold]before committing[/bold] (stdlib → third-party → local).[/green]"

                else:
                    return "[green]💡 Reorder imports: standard library → third-party → local imports.[/green]"

            elif "should be in" in issue.message.lower():
                if has_changes:
                    return "[green]✏️ Fix naming [bold]before committing[/bold] to follow PEP 8 conventions.[/green]"

                else:
                    return "[green]💡 Follow PEP 8 naming conventions (snake_case, CamelCase, UPPER_CASE).[/green]"

            elif "trailing whitespace" in issue.message.lower():
                if has_changes:
                    return "[green]🧹 Remove trailing whitespace [bold]before committing[/bold].[/green]"

                else:
                    return "[green]💡 Remove trailing whitespace for cleaner code.[/green]"

            elif "function arguments" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Refactor function [bold]before committing[/bold] to reduce arguments.[/green]"

                else:
                    return "[green]💡 Consider refactoring function with too many arguments.[/green]"
                
            elif "inline comment" in issue.message.lower():
                if has_changes:
                    return (
                        "[green]🗒️ Inline comment detected on a code line — "
                        "move the comment to a separate line above the code or keep only "
                        "allowed markers (e.g. `# type: ignore`) [bold]before committing[/bold].[/green]"
                    )

                else:
                    return (
                        "[green]💡 Prefer placing comments on their own line or using docstrings; "
                        "inline comments reduce readability unless they are short and necessary.[/green]"
                    )

            else:
                if has_changes:
                    return "[green]📝 Fix PEP 8 issue [bold]before committing[/bold] to improve code style.[/green]"

                else:
                    return "[green]💡 Fix this PEP 8 style guide violation.[/green]"


        if has_changes:
            return "[blue]📝 Review this code [bold]before committing[/bold] to ensure quality.[/blue]"

        else:
            return "[blue]👀 This code could benefit from review and improvement.[/blue]"
import ast
from pathlib import Path
from typing import Optional

from .models import CodeIssue, ReviewConfig, SeverityLevel
from .git_utils import GitRepo
from ..configuration import MAX_LINES_FUNCTION, MAX_COMPLEXITY, MAX_LINE_LENGTH_PEP8, MAX_BLANK_LINES


class CodeAnalyzer:
    """Main code analyzer class with Git support."""

    def __init__(self, config: Optional[ReviewConfig] = None, repo_path: Path = Path(".")) -> None:
        self.config = config or ReviewConfig()
        self.git_repo = GitRepo(repo_path)

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


    def analyze_file(self, file_path: Path, content: Optional[str] = None) -> list[CodeIssue]:
        """Analyze single Python file."""
        issues: list[CodeIssue] = []

        try:
            if content is None:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()

            if content is not None and getattr(self.git_repo, "get_staged_diff_for_file", None):
                file_diff = self.git_repo.get_staged_diff_for_file(file_path)
            else:
                file_diff = self.git_repo.get_diff_for_file(file_path)

            tree = ast.parse("".join(lines), filename=str(file_path))


            issues.extend(self._check_magic_numbers(tree, file_path))
            issues.extend(self._check_long_functions(tree, file_path))
            issues.extend(self._check_unused_imports(tree, file_path))
            issues.extend(self._check_complex_functions(tree, file_path))
            issues.extend(self._check_undefined_variables(tree, file_path))
            issues.extend(self._check_unused_variables(tree, file_path))
            issues.extend(self._check_type_annotations(tree, file_path))
            issues.extend(self._check_pep8(tree, file_path))
            issues.extend(self._check_inline_comments(file_path))
            issues.extend(self._check_pep257_docstrings(tree, file_path, lines))
            issues.extend(self._check_bare_except(tree, file_path))

            # Add Git context to issues
            for issue in issues:
                issue.suggestion = self._get_git_aware_suggestion(issue, file_diff or "")


        except (SyntaxError, UnicodeDecodeError, Exception) as e:
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

        # First pass: collect line numbers of constants that are assigned to module-level UPPER_CASE names
        # or annotated with Final — these should NOT be treated as magic numbers.
        exempt_lines: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # value can be constant or tuple/list of constants
                value = node.value
                is_value_numeric_const = False
                const_line = getattr(value, "lineno", None)

                if isinstance(value, ast.Constant) and isinstance(value.value, (int, float)):
                    is_value_numeric_const = True

                elif isinstance(value, (ast.Tuple, ast.List)):
                    # if all elements are numeric constants — consider exempt if target is UPPER_CASE
                    elems = [e for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, (int, float))]
                    if elems and len(elems) == len(value.elts):
                        is_value_numeric_const = True
                        const_line = getattr(value.elts[0], "lineno", const_line)

                if is_value_numeric_const:
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name) and tgt.id.isupper():
                            if const_line:
                                exempt_lines.add(const_line)

                            else:
                                exempt_lines.add(node.lineno)

            # Annotated assignment: NAME: Final[...] = CONST  or NAME: "Final[int]" = CONST
            elif isinstance(node, ast.AnnAssign):
                target = node.target
                if isinstance(target, ast.Name):
                    ann = node.annotation
                    # if annotated as Final[...] or target is uppercase -> exempt
                    if (ann is not None and self._annotation_is_final(ann)) or target.id.isupper():
                        exempt_lines.add(node.lineno)


        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                number = node.value

                if number in ignored_numbers or getattr(node, "lineno", None) in exempt_lines:
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

        # Start with whatever the existing collector gives (if available)
        try:
            base_defined = set(self._collect_defined_names(tree) or [])

        except Exception:
            base_defined = set()

        def _extract_names_from_target(node: ast.AST) -> set[str]:
            """Recursively extract simple variable names from assignment/target nodes."""
            names: set[str] = set()
            if isinstance(node, ast.Name):
                names.add(node.id)

            elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                for elt in node.elts:
                    names.update(_extract_names_from_target(elt))
            elif isinstance(node, ast.Starred):
                names.update(_extract_names_from_target(node.value))

            # ignore Attribute (obj.attr) because it doesn't create a new local name
            # ignore Subscript and other complex targets

            return names

        defined_names: set[str] = set(base_defined)


        for node in ast.walk(tree):
            # regular assignments: a = ..., a, b = ...
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    defined_names.update(_extract_names_from_target(tgt))

            # annotated assignments: x: int = 1  or x: Final[int] = 1
            elif isinstance(node, ast.AnnAssign):
                target = node.target
                if isinstance(target, ast.Name):
                    defined_names.add(target.id)

                else:
                    defined_names.update(_extract_names_from_target(target))

            # for loops: for x in ... / async for
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                defined_names.update(_extract_names_from_target(node.target))

            # comprehensions: genexp, listcomp, setcomp, dictcomp have ast.comprehension nodes
            elif isinstance(node, ast.comprehension):
                defined_names.update(_extract_names_from_target(node.target))

            # with ... as var:
            elif isinstance(node, ast.With):
                for item in node.items:
                    if getattr(item, "optional_vars", None) is not None:
                        defined_names.update(_extract_names_from_target(item.optional_vars))

            # exception handler: except Exception as e:
            elif isinstance(node, ast.ExceptHandler):
                if getattr(node, "name", None):
                    if isinstance(node.name, str):
                        defined_names.add(node.name)

                    elif isinstance(node.name, ast.Name):
                        defined_names.add(node.name.id)

            # function and async function defs: function name + arg names
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined_names.add(node.name)
                # positional / kw / vararg / kwarg / posonly / kwonly
                for arg in getattr(node.args, "posonlyargs", []) + node.args.args + node.args.kwonlyargs:
                    if getattr(arg, "arg", None):
                        defined_names.add(arg.arg)

                if node.args.vararg and getattr(node.args.vararg, "arg", None):
                    defined_names.add(node.args.vararg.arg)

                if node.args.kwarg and getattr(node.args.kwarg, "arg", None):
                    defined_names.add(node.args.kwarg.arg)

            # class definitions: class name
            elif isinstance(node, ast.ClassDef):
                defined_names.add(node.name)

            # imports: import x as y  -> y or x (if no as)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.asname:
                        defined_names.add(alias.asname)

                    else:
                        # top-level name only (module package)
                        if alias.name:
                            defined_names.add(alias.name.split('.')[0])

        used_names = self._collect_used_names(tree)

        for name, line in used_names:
            if name in defined_names or self._is_builtin(name) or (name.startswith("__") and name.endswith("__")):
                continue

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

        final_vars: set[str] = set()
        for node in ast.walk(tree):
            # only consider annotated assignments (AnnAssign) with simple name target
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.annotation:
                if self._annotation_is_final(node.annotation):
                    final_vars.add(node.target.id)

        used_variables = self._collect_used_variables(tree)
        defined_variables = self._collect_defined_variables(tree)

        for var_name, (line, var_type) in defined_variables.items():
            if var_name.isupper() or var_name in final_vars:
                continue

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
        issues.extend(self._check_whitespace("".join(lines), file_path))
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
                ann = node.annotation
                is_final = self._annotation_is_final(ann)

                if is_final:
                    continue

                issues.extend(self._check_single_annotation(node, file_path))
                if type_mismatch_rule and type_mismatch_rule.enabled and getattr(node, "value", None):
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


    def _check_function_annotations(self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> list[CodeIssue]:
        """Check type annotations for a function."""
        issues: list[CodeIssue] = []
        missing_annotation_rule = self.config.rules.get("missing_type_annotation")
        if not missing_annotation_rule or not missing_annotation_rule.enabled:
            return issues

        SKIP_PARAM_NAMES = {"self", "cls", "mcs"}

        args = node.args

        for arg in args.args:
            name = getattr(arg, "arg", None)
            if not name:
                continue

            if name in SKIP_PARAM_NAMES:
                continue

            if getattr(arg, "annotation", None) is None:
                issues.append(CodeIssue(
                    file=file_path,
                    line=getattr(arg, "lineno", node.lineno),
                    message=f"❌ [bold yellow]Missing type annotation for parameter:[/bold yellow] {name}",
                    severity=missing_annotation_rule.severity,
                    rule_id="missing_type_annotation",
                    suggestion="[italic]Add a type annotation for the parameter (e.g. `name: str`).[/italic]"
                ))


        if getattr(args, "vararg", None):
            var = args.vararg
            name = getattr(var, "arg", None)
            if name and name not in SKIP_PARAM_NAMES and getattr(var, "annotation", None) is None:
                issues.append(CodeIssue(
                    file=file_path,
                    line=getattr(var, "lineno", node.lineno),
                    message=f"❌ [bold yellow]Missing type annotation for var-positional parameter:[/bold yellow] *{name}",
                    severity=missing_annotation_rule.severity,
                    rule_id="missing_type_annotation",
                    suggestion="[italic]Annotate varargs like `*args: tuple[int, ...]` or `*args: Any`.[/italic]"
                ))


        if getattr(args, "kwarg", None):
            kw = args.kwarg
            name = getattr(kw, "arg", None)
            if name and name not in SKIP_PARAM_NAMES and getattr(kw, "annotation", None) is None:
                issues.append(CodeIssue(
                    file=file_path,
                    line=getattr(kw, "lineno", node.lineno),
                    message=f"❌ [bold yellow]Missing type annotation for var-keyword parameter:[/bold yellow] **{name}",
                    severity=missing_annotation_rule.severity,
                    rule_id="missing_type_annotation",
                    suggestion="[italic]Annotate kwargs like `**kwargs: dict[str, Any]` or `**kwargs: Any`.[/italic]"
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


    def _check_type_mismatch(self, node: ast.AnnAssign, file_path: Path) -> list[CodeIssue]:
        """Check simple type mismatches between annotation and assigned value."""
        issues: list[CodeIssue] = []
        type_mismatch_rule = self.config.rules.get("type_mismatch")
        if not type_mismatch_rule or not type_mismatch_rule.enabled:
            return issues

        def _annotation_base(a: ast.AST) -> Optional[str]:
            # ast.Subscript (like list[int], List[int], etc.)
            if isinstance(a, ast.Subscript):
                return _annotation_base(a.value)

            # Name: list, int, etc.
            if isinstance(a, ast.Name):
                return a.id.lower()

            # Attribute: typing.List -> attr == 'List' -> list
            if isinstance(a, ast.Attribute):
                return getattr(a, "attr", None).lower() if getattr(a, "attr", None) else None

            # Constant string annotation (from __future__ annotations)
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                s = a.value.strip()
                if s:
                    base = s.split("[", 1)[0].split(".", 1)[-1]
                    return base.lower()

                return None

            return None

        def _value_base(v: ast.AST) -> Optional[str]:
            # Literal list/tuple/set/dict / comprehensions
            if isinstance(v, (ast.List, ast.ListComp)):
                return "list"

            if isinstance(v, (ast.Tuple, ast.TupleComp)) if hasattr(ast, "TupleComp") else isinstance(v, ast.Tuple):
                # TupleComp not present in all Python AST variants; fallback above
                return "tuple"

            if isinstance(v, ast.Set):
                return "set"

            if isinstance(v, ast.Dict):
                return "dict"

            # Constants: numbers/str/bool
            if isinstance(v, ast.Constant):
                val = v.value
                return type(val).__name__.lower() if val is not None else None

            # Call like list(...), dict(...), or factory function
            if isinstance(v, ast.Call):
                func = v.func
                if isinstance(func, ast.Name):
                    return func.id.lower()

                if isinstance(func, ast.Attribute):
                    # e.g. collections.defaultdict(...) -> attribute name
                    return getattr(func, "attr", None).lower() if getattr(func, "attr", None) else None

            # Fallback: we cannot infer
            return None


        ann_base = _annotation_base(node.annotation) if getattr(node, "annotation", None) else None
        value_node = getattr(node, "value", None)
        value_base = _value_base(value_node) if value_node is not None else None

        if not ann_base or not value_base:
            return issues

        # Normalize some common synonyms from typing (List -> list, Dict -> dict, etc.)
        synonyms = {
            "list": {"list"},
            "dict": {"dict"},
            "tuple": {"tuple"},
            "set": {"set"},
            "str": {"str"},
            "int": {"int"},
            "float": {"float"},
            "bool": {"bool"},
        }

        # If annotation is a typing alias like 'list'/'list' -> handled via ann_base already.
        # Consider match when both bases belong to same family (e.g., annotation 'list' and value 'list').
        match = False
        if ann_base == value_base:
            match = True

        else:
            for k, v in synonyms.items():
                if ann_base == k and value_base in v:
                    match = True
                    break

        if not match:
            issues.append(CodeIssue(
                file=file_path,
                line=getattr(node, "lineno", 0),
                message=f"❌ [bold yellow]Type mismatch:[/bold yellow] {getattr(node.target, 'id', 'value')} is annotated as {ann_base} but assigned {value_base}",
                severity=type_mismatch_rule.severity,
                rule_id="type_mismatch",
                suggestion="[italic]Fix the annotation or the assigned value so their types match.[/italic]"
            ))

        return issues


    def _check_return_type_mismatch(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: Path) -> list[CodeIssue]:
        """Check if function return type matches the actual returned values."""
        issues: list[CodeIssue] = []

        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not func_node.returns:
            return issues

        return_annotation = (self._annotation_to_string(func_node.returns) or "").strip()
        return_types = self._get_function_return_types(func_node) or []

        if not return_annotation or not return_types:
            return issues

        # A set of markers that mean "unknown/uninformative"
        UNKNOWN_TOKENS = {"unknown", "<unknown>", "any", "anytype", "none", "nonetype", "none_type", "mixed"}

        def is_informative_type(s: str) -> bool:
            """Вернёт True, если строка выглядит как осмысленный тип."""
            if not s or not isinstance(s, str):
                return False

            s2 = s.strip()
            if not s2:
                return False

            low = s2.lower()
            if low in UNKNOWN_TOKENS:
                return False

            if s2 == func_node.name:
                return False

            builtin_simple = {"int", "str", "bool", "float", "list", "dict", "set", "tuple", "bytes", "none"}
            if low in builtin_simple:
                return True

            if ("[" in s2 and "]" in s2) or "." in s2 or "typing." in s2 or "optional" in low or "union" in low or "|" in s2:
                return True

            if s2 and s2[0].isupper():
                return True

            if any(tok in low for tok in ("list", "dict", "tuple", "set", "iter", "sequence", "mapping", "callable")):
                return True

            return False

        normed: list[str] = []
        for rt in return_types:
            if not rt or not isinstance(rt, str):
                continue

            s = rt.strip()
            if s:
                normed.append(s)

        if not any(is_informative_type(t) for t in normed):
            return issues

        filtered_return_types = [t for t in normed if is_informative_type(t)]
        if not filtered_return_types:
            return issues

        def canonical_base(s: str) -> str:
            if not s:
                return ""

            s = s.strip()
            if s.startswith("typing."):
                s = s[len("typing."):]

            if "[" in s:
                s = s.split("[", 1)[0]

            return s.strip()

        base_annotations: list[str] = [return_annotation]
        ann = return_annotation
        ann_low = ann.lower()

        if (ann.startswith("Optional[") and ann.endswith("]")) or (ann.startswith("typing.Optional[") and ann.endswith("]")):
            inner = ann.split("[", 1)[1][:-1].strip()
            base_annotations = [inner, "None"]

        elif (ann.startswith("Union[") and ann.endswith("]")) or (ann.startswith("typing.Union[") and ann.endswith("]")):
            inner = ann.split("[", 1)[1][:-1]
            parts = [p.strip() for p in inner.split(",") if p.strip()]
            base_annotations = parts or base_annotations

        elif "|" in ann:
            parts = [p.strip() for p in ann.split("|") if p.strip()]
            if parts:
                base_annotations = parts
    
        elif ann_low == "none":
            base_annotations = ["None"]

        base_annotations = [canonical_base(b) for b in base_annotations if b]

        def types_compatible_with_heuristics(base_ann: str, ret_type: str) -> bool:
            base_ann_s = (base_ann or "").strip()
            ret_s = (ret_type or "").strip()
            if not base_ann_s or not ret_s:
                return False

            if base_ann_s.lower() in UNKNOWN_TOKENS or ret_s.lower() in UNKNOWN_TOKENS:
                return True

            try:
                if self._types_are_compatible(base_ann_s, ret_s):
                    return True

            except Exception:
                pass

            bc = canonical_base(base_ann_s).lower()
            rc = canonical_base(ret_s).lower()

            if bc and rc and bc == rc:
                return True

            # int <-> bool: in Python bool is a subclass of int, often 0/1 are used as boolean values
            if bc == "bool" and rc == "int":
                return True

            synonyms = {
                "list": {"list"},
                "dict": {"dict"},
                "tuple": {"tuple"},
                "set": {"set"},
                "str": {"str"},
                "int": {"int"},
                "float": {"float"},
                "bool": {"bool"}
            }

            if bc in synonyms and rc in synonyms.get(bc, {rc}):
                return True

            return False

        for return_type in filtered_return_types:
            compatible = False
            for base_ann in base_annotations:
                if types_compatible_with_heuristics(base_ann, return_type):
                    compatible = True
                    break

            if not compatible:
                issues.append(CodeIssue(
                    file=file_path,
                    line=func_node.lineno,
                    message=(
                        f"❌ [bold yellow]Return type mismatch:[/bold yellow] "
                        f"Function [bold]{func_node.name}[/bold] returns [red]{return_type}[/red] "
                        f"but annotated as [yellow]{return_annotation}[/yellow]"
                    ),
                    severity=SeverityLevel.INFO,
                    rule_id="type_mismatch",
                    suggestion="[italic]Fix the return type annotation or the returned values to resolve the type conflict.[/italic]"
                ))
                break  # One error per function is enough

        return issues

    # ==================== PEP 8 CHECKS ====================

    def _check_line_length(self, lines: list[str], file_path: Path) -> list[CodeIssue]:
        """
        Check if lines exceed maximum length (PEP 8: 79 characters).

        Supports two modes controlled by pep8 rule parameter `line_mode`:
        - "pep8" (default)      : count full line length (including leading indent)
        - "strip_indent"        : ignore leading whitespace when counting length
        """
        issues: list[CodeIssue] = []
        pep8_rule = self.config.rules.get("pep8")

        # default mode = pep8 (count full line, including indent)
        line_mode = "pep8"
        if pep8_rule and pep8_rule.parameters:
            line_mode = str(pep8_rule.parameters.get("line_mode", "pep8")).lower()

        for i, line in enumerate(lines, 1):
            line_no_newline = line.rstrip("\r\n")
            length = 0

            # compute length according to selected mode
            if line_mode == "strip_indent":
                length = len(line_no_newline.lstrip())

            else:
                # default PEP8 behaviour: count entire line, including leading spaces
                length = len(line_no_newline)

            if length > MAX_LINE_LENGTH_PEP8:
                # skip obvious false-positives (URLs, pragmas, type comments)
                if not any(x in line_no_newline for x in ["http://", "https://", "pragma:", "type:"]):
                    issues.append(CodeIssue(
                        file=file_path,
                        line=i,
                        message=f"❌ [bold yellow]Line too long ({length} > {MAX_LINE_LENGTH_PEP8} characters)[/bold yellow]",
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

        # Build a parent map so we can determine whether a node is module-level
        parents: dict[ast.AST, ast.AST] = {}

        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        def _is_module_level(node: ast.AST) -> bool:
            """Return True if the node is at module level (not inside function/class)."""
            cur = node
            while cur in parents:
                cur = parents[cur]
                if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    return False

            return True

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
                # Only consider single-target simple name assignments that are at module level.
                # This avoids flagging local temporaries like `is_keyword_or_default`.
                if (len(node.targets) == 1 and
                    isinstance(node.targets[0], ast.Name) and
                    _is_module_level(node) and
                    self._is_constant_name(node.targets[0].id)):

                    name = node.targets[0].id
                    if not name.isupper():
                        issues.append(CodeIssue(
                            file=file_path,
                            line=node.lineno,
                            message=f"❌ [bold yellow]Constant should be in UPPER_CASE: {name}[/bold yellow]",
                            severity=SeverityLevel.INFO,
                            rule_id="pep8",
                            suggestion="[italic]Use UPPER_CASE for constants (e.g., MAX_VALUE).[/italic]"
                        ))

        return issues


    def _check_whitespace(self, content: str, file_path: Path) -> list[CodeIssue]:
        """Whitespace checks according to PEP 8 (best-effort)."""
        issues: list[CodeIssue] = []
        pep8_rule = self.config.rules.get("pep8")
        if not pep8_rule or not pep8_rule.enabled:
            return issues

        severity = pep8_rule.severity or SeverityLevel.INFO

        import io
        import tokenize

        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))

        except Exception:
            return issues

        IGNORE = {
            tokenize.NL, tokenize.NEWLINE, tokenize.ENCODING,
            tokenize.ENDMARKER, tokenize.INDENT, tokenize.DEDENT
        }

        def prev_sig(idx: int) -> Optional[tokenize.TokenInfo]:
            j = idx - 1
            while j >= 0 and tokens[j].type in IGNORE:
                j -= 1

            return tokens[j] if j >= 0 else None


        def next_sig(idx: int) -> Optional[tokenize.TokenInfo]:
            j = idx + 1
            while j < len(tokens) and tokens[j].type in IGNORE:
                j += 1

            return tokens[j] if j < len(tokens) else None

        # Track bracket depth for contextual checks (slices, calls, etc.)
        bracket_stack: list[tuple[str, tokenize.TokenInfo]] = []

        # Operators considered binary for spacing checks
        BINARY_OPS = {
            "+", "-", "*", "/", "//", "%", "**",
            "<<", ">>", "&", "|", "^",
            "==", "!=", "<", ">", "<=", ">="
        }


        for i, tok in enumerate(tokens):
            ttype = tok.type
            tstr = tok.string
            start_line, start_col = tok.start
            end_line, end_col = tok.end

            # Track opening/closing brackets to know context (call, index, slice, etc.)
            if tstr in ("(", "[", "{"):
                bracket_stack.append((tstr, tok))

            elif tstr in (")", "]", "}"):
                if bracket_stack:
                    bracket_stack.pop()


            # 1) Space immediately after opening bracket is not allowed
            if tstr in ("(", "[", "{"):
                nxt = next_sig(i)
                if nxt and nxt.start[1] > end_col:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Unexpected space after opening bracket '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Remove the space after the opening bracket.[/italic]"
                    ))


            # 2) Space immediately before closing bracket is not allowed
            if tstr in (")", "]", "}"):
                prev = prev_sig(i)
                if prev and start_col > prev.end[1]:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Unexpected space before closing bracket '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Remove the space before the closing bracket.[/italic]"
                    ))


            # 3) Comma / semicolon handling (no space before punctuation; reasonable spacing after)
            if ttype == tokenize.OP and tstr in {",", ";"}:
                prev = prev_sig(i)
                nxt = next_sig(i)
                if prev and start_col > prev.end[1]:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Unexpected space before '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Remove the space before the punctuation mark.[/italic]"
                    ))

                if nxt and nxt.start[1] - end_col > 1:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Too many spaces after '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Use a single space after commas/semicolons where appropriate.[/italic]"
                    ))


            # 4) Colon handling (slices vs annotations vs dict keys)
            if ttype == tokenize.OP and tstr == ":":
                # compute surrounding tokens with indices (we need index to detect dict-key context)
                j = i - 1
                while j >= 0 and tokens[j].type in IGNORE:
                    j -= 1

                prev = tokens[j] if j >= 0 else None

                k = i + 1
                while k < len(tokens) and tokens[k].type in IGNORE:
                    k += 1

                nxt = tokens[k] if k < len(tokens) else None

                # token before the previous (to detect '{' or ',' before a key in a dict literal)
                bj = j - 1
                while bj >= 0 and tokens[bj].type in IGNORE:
                    bj -= 1

                before_prev = tokens[bj] if bj >= 0 else None

                in_brackets = any(b for b in bracket_stack if b[0] == "[")

                # --- Annotations ---
                # If the ':' is preceded by a name (NAME) and the ':' is followed by a name/string/type (NAME/STRING) as expected,
                # then most likely this is a parameter or variable annotation (x: str, arg: "T").
                is_annotation_like = False
                if prev and prev.type == tokenize.NAME and nxt:
                    if nxt.type == tokenize.NAME or nxt.type == tokenize.STRING:
                        is_annotation_like = True

                # --- Mapping key (dict literal) detection ---
                # If the token before the key is '{' or ',', then prev is likely a dict key (string/name/number).
                is_mapping_key = False
                if prev and before_prev and before_prev.string in ("{", ","):
                    if prev.type in (tokenize.STRING, tokenize.NAME, tokenize.NUMBER):
                        is_mapping_key = True

                if is_annotation_like or is_mapping_key:
                    continue

                # If the next significant token is on another line, this ':' most likely
                # terminates a block (if/for/def/class/while/etc.) — skip "space after" check.
                if nxt and nxt.start[0] != start_line:
                    # keep checking "space before ':'" below, but skip checking "after" since colon ends the line
                    # (nothing to do for 'after' in this case)
                    if prev and start_col > prev.end[1]:
                        if not (in_brackets and prev.string in ("[", ",")):
                            issues.append(CodeIssue(
                                file=file_path,
                                line=start_line,
                                message="❌ [bold yellow]Unexpected space before ':'[/bold yellow]",
                                severity=severity,
                                rule_id="pep8",
                                suggestion="[italic]Remove spaces before ':' unless using extended slice with omitted elements.[/italic]"
                            ))

                    continue

                if prev and start_col > prev.end[1]:
                    if in_brackets and prev.string in ("[", ","):
                        pass

                    else:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message="❌ [bold yellow]Unexpected space before ':'[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Remove spaces before ':' unless using extended slice with omitted elements.[/italic]"
                        ))

                if nxt and nxt.start[1] > end_col:
                    if not (in_brackets and nxt.string == "]" and prev and prev.string in ("[", ",")):
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message="❌ [bold yellow]Unexpected space after ':'[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Remove spaces after ':' unless using extended slice with omitted elements.[/italic]"
                        ))


            # 5) Function call spacing: no space before '(' when calling
            if tstr == "(":
                prev = prev_sig(i)
                if prev and prev.type == tokenize.NAME and start_col > prev.end[1]:
                    # Exception: allow "except (" constructs (not a function call)
                    # and allow "in (" contexts (e.g. for x in (1, 2):)
                    if prev.string.lower() in ("except", "in", "or", "and", "if", "elif", "return", "not"):
                        pass

                    else:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message="❌ [bold yellow]Unexpected space before '(' in function call[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Remove space before '(' when calling a function.[/italic]"
                        ))


            # 6) Binary operators and '=' handling
            if ttype == tokenize.OP and (tstr in BINARY_OPS or tstr == "="):
                prev = prev_sig(i)
                nxt = next_sig(i)
                if not prev or not nxt:
                    continue

                left_is_value = prev.type in (tokenize.NAME, tokenize.NUMBER, tokenize.STRING)
                right_is_value = nxt.type in (tokenize.NAME, tokenize.NUMBER, tokenize.STRING)

                left_spaces = start_col - prev.end[1]
                right_spaces = nxt.start[1] - end_col

                # Too many spaces (more than one) on either side
                if left_spaces > 1:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Too many spaces before operator '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Use a single space around binary operators.[/italic]"
                    ))

                if right_spaces > 1:
                    issues.append(CodeIssue(
                        file=file_path,
                        line=start_line,
                        message=f"❌ [bold yellow]Too many spaces after operator '{tstr}'[/bold yellow]",
                        severity=severity,
                        rule_id="pep8",
                        suggestion="[italic]Use a single space around binary operators.[/italic]"
                    ))

                # Exceptions for '=': kwarg/default/annotation contexts
                is_keyword_or_default = False
                if tstr == "=":
                    in_parens = any(b for b in bracket_stack if b[0] == "(")
                    if in_parens and prev.type == tokenize.NAME:
                        is_keyword_or_default = True

                    # look behind for ':' (annotation case like "x: T = v")
                    j = i - 1
                    while j >= 0 and tokens[j].type in IGNORE:
                        j -= 1

                    if j >= 0 and tokens[j].string == ":":
                        is_keyword_or_default = True

                # Missing spaces for binary-like operators (but not for keyword/default cases)
                is_binary_like = left_is_value and right_is_value
                if is_binary_like and not (tstr == "=" and is_keyword_or_default):
                    if left_spaces == 0 or right_spaces == 0:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message=f"❌ [bold yellow]Missing spaces around operator '{tstr}'[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Use a single space around binary operators, e.g. `a + b`.[/italic]"
                        ))

            # 7) Duplicate guard: multiple spaces around operators (safety net)
            if ttype == tokenize.OP and tstr in {
                "=", "+=", "-=", "*=", "/=", "//=", "%=", "@=",
                "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "//", "%", "**", "|", "&", "^", ">>", "<<"
            }:
                prev = prev_sig(i)
                nxt = next_sig(i)
                if prev:
                    left_spaces = start_col - prev.end[1]
                    if left_spaces > 1:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message=f"❌ [bold yellow]Too many spaces before operator '{tstr}'[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Use a single space around binary operators.[/italic]"
                        ))

                if nxt:
                    right_spaces = nxt.start[1] - end_col
                    if right_spaces > 1:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=start_line,
                            message=f"❌ [bold yellow]Too many spaces after operator '{tstr}'[/bold yellow]",
                            severity=severity,
                            rule_id="pep8",
                            suggestion="[italic]Use a single space around binary operators.[/italic]"
                        ))

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


    def _annotation_is_final(self, ann: ast.AST) -> bool:
        """
        Return True if the annotation AST node represents Final[...] (typing.Final or attribute form).
        Also handles string annotations that contain 'Final'.
        """
        if ann is None:
            return False

        base = ann.value if isinstance(ann, ast.Subscript) else ann

        if isinstance(base, ast.Name) and base.id == "Final":
            return True

        if isinstance(base, ast.Attribute) and getattr(base, "attr", None) == "Final":
            return True

        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            return "Final" in ann.value

        return False


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


    def _check_pep257_docstrings(self, tree: ast.AST, file_path: Path, lines: list[str]) -> list[CodeIssue]:
        """
        PEP 257: Check multi-line docstrings formatting.
        - Closing triple quotes must be on their own line.
        - Prefer (soft recommendation) having an empty line before the closing quotes.
        """
        issues: list[CodeIssue] = []
        pep8_rule = self.config.rules.get("pep8")

        if not pep8_rule or not pep8_rule.enabled:
            return issues

        def _check_docnode(docnode: ast.Expr) -> None:
            # docnode.value is ast.Constant (string)
            val = getattr(docnode, "value", None)
            if val is None:
                return


            if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
                return

            start = getattr(val, "lineno", None)
            end = getattr(val, "end_lineno", None) or start

            # single-line docstring -> skip
            if start is None or end is None or end == start:
                return

            last_line: str = ""

            try:
                last_line = lines[end - 1].rstrip('\r\n')

            except Exception:
                pass

            stripped_last = last_line.strip()

            if stripped_last not in ('"""', "'''"):
                issues.append(CodeIssue(
                    file=file_path,
                    line=end,
                    message="❌ [bold yellow]Docstring closing quotes should be on a separate line[/bold yellow]",
                    severity=SeverityLevel.INFO,
                    rule_id="pep8",
                    suggestion="[italic]Put the closing triple quotes on their own line (and optionally leave a blank line before them).[/italic]"
                ))

                return

            # prefer blank line before closing quotes (soft recommendation)
            # check previous line (end - 2 index)
            prev_idx = end - 2
            if prev_idx >= 0:
                prev_line: str = ""

                try:
                    prev_line = lines[prev_idx].rstrip('\r\n')

                except Exception:
                    pass

                # if previous line is not blank (contains text other than whitespace),
                if prev_line.strip() != "":
                    issues.append(CodeIssue(
                        file=file_path,
                        line=end,
                        message="❌ [bold yellow]Prefer an empty line before the closing docstring quotes[/bold yellow]",
                        severity=SeverityLevel.INFO,
                        rule_id="pep8",
                        suggestion="[italic]Add a blank line before the closing triple quotes to separate body and end marker.[/italic]"
                    ))


        if isinstance(tree, ast.Module) and tree.body:
            first = tree.body[0]
            if isinstance(first, ast.Expr):
                _check_docnode(first)


        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.body:
                    first_stmt = node.body[0]
                    if isinstance(first_stmt, ast.Expr):
                        _check_docnode(first_stmt)

        return issues


    def _check_bare_except(self, tree: ast.AST, file_path: Path) -> list[CodeIssue]:
        """Detect bare `except:` handlers and warn (INFO)."""
        issues: list[CodeIssue] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    # bare except: handler.type is None for "except:"
                    if handler.type is None:
                        issues.append(CodeIssue(
                            file=file_path,
                            line=getattr(handler, "lineno", 1),
                            message="❌ [bold yellow]Use `except Exception:` or catch specific exceptions instead of bare `except:`[/bold yellow]",
                            severity=SeverityLevel.INFO,
                            rule_id="pep8",
                            suggestion="[italic]Avoid `except:` because it catches system-exiting exceptions (KeyboardInterrupt, SystemExit). Prefer `except Exception:` or specific exception classes.[/italic]"
                        ))

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
            if "line too long" in issue.message.lower() or "too long" in issue.message.lower():
                if has_changes:
                    return "[green]📏 Break long line [bold]before committing[/bold] to improve readability.[/green]"

                else:
                    return "[green]💡 Break long lines to comply with PEP 8 (79 characters) or your project's policy.[/green]"

            if "blank lines" in issue.message.lower() or "too many blank" in issue.message.lower():
                if has_changes:
                    return "[green]📝 Fix blank lines [bold]before committing[/bold] to follow PEP 8.[/green]"

                else:
                    return "[green]💡 Use proper blank line spacing (max 2 lines between top-level definitions).[ /green]"


            if "import order" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Reorder imports [bold]before committing[/bold] (stdlib → third-party → local).[/green]"

                else:
                    return "[green]💡 Reorder imports: standard library → third-party → local imports.[/green]"

            if "should be in" in issue.message.lower() or "class name should" in issue.message.lower() or "function name should" in issue.message.lower() or "constant should" in issue.message.lower():
                if has_changes:
                    return "[green]✏️ Fix naming [bold]before committing[/bold] to follow PEP 8 conventions (snake_case, CamelCase, UPPER_CASE).[/green]"

                else:
                    return "[green]💡 Follow PEP 8 naming conventions (snake_case for functions/variables, CamelCase for classes, UPPER_CASE for constants).[/green]"

            if "trailing whitespace" in issue.message.lower():
                if has_changes:
                    return "[green]🧹 Remove trailing whitespace [bold]before committing[/bold].[/green]"

                else:
                    return "[green]💡 Remove trailing whitespace for cleaner code and to avoid pre-commit hook failures.[/green]"

            if "inline comment" in issue.message.lower():
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

            if "unexpected space after opening bracket" in issue.message.lower() or "unexpected space after" in issue.message.lower() and ("(" in issue.message.lower() or "[" in issue.message.lower() or "{" in issue.message.lower()):
                if has_changes:
                    return "[green]🔧 Remove the space immediately after the opening bracket [bold]before committing[/bold] (e.g. use `spam(ham[1])` not `spam( ham[ 1 ] )`).[/green]"

                else:
                    return "[green]💡 Avoid spaces right after '(' or '[' or '{' — they should be written as `spam(ham[1])`.[/green]"

            if "unexpected space before closing bracket" in issue.message.lower() or "unexpected space before" in issue.message.lower() and (")" in issue.message.lower() or "]" in issue.message.lower() or "}" in issue.message.lower()):
                if has_changes:
                    return "[green]🔧 Remove the space before the closing bracket [bold]before committing[/bold] (e.g. use `lst[1]` not `lst[ 1 ]`).[/green]"

                else:
                    return "[green]💡 Avoid spaces immediately before `)`, `]` or `}`.[/green]"

            if "unexpected space before" in issue.message.lower() and ("," in issue.message.lower() or "comma" in issue.message.lower() or ";" in issue.message.lower() or "semicolon" in issue.message.lower() or ":" in issue.message.lower() or "colon" in issue.message.lower()):
                if ":" in issue.message.lower() or "colon" in issue.message.lower():
                    if has_changes:
                        return "[green]🔧 Remove the space before ':' [bold]before committing[/bold] unless it's part of an extended slice with omitted elements — follow PEP 8 slice spacing rules.[/green]"

                    else:
                        return "[green]💡 In slicing contexts `:` acts like an operator; avoid spaces around it unless you intentionally omit parameters (e.g., `a[:9]`).[/green]"

                else:
                    punct = ","
                    if ";" in issue.message.lower() or "semicolon" in issue.message.lower():
                        punct = ";"

                    if has_changes:
                        return f"[green]🔧 Remove the space before `{punct}` [bold]before committing[/bold]. Punctuation should directly follow the previous token.[/green]"

                    else:
                        return f"[green]💡 No space should appear directly before `{punct}`.[/green]"

            if "unexpected space before '(' in function call" in issue.message.lower() or "unexpected space before '('" in issue.message.lower() and "function" in issue.message.lower() or "space before (' in function" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Remove the space between function name and '(' [bold]before committing[/bold] (e.g. use `spam(1)` not `spam (1)`).[/green]"

                else:
                    return "[green]💡 Don't put a space before '(' when calling a function.[/green]"

            if "unexpected space before" in issue.message.lower() and ("['" in issue.message.lower() or '["' in issue.message.lower() or "index" in issue.message.lower()):
                if has_changes:
                    return "[green]🔧 Remove the space before indexing/slicing [bold]before committing[/bold] (e.g. use `dct['key']` not `dct ['key']`).[/green]"

                else:
                    return "[green]💡 Avoid spaces between an object and '[' when indexing: use `obj[index]`.[/green]"

            if "too many spaces before operator" in issue.message.lower() or "too many spaces after operator" in issue.message.lower() or ("too many spaces" in issue.message.lower() and "operator" in issue.message.lower()):
                if has_changes:
                    return "[green]🔧 Reduce multiple spaces around operators to a single space [bold]before committing[/bold] (e.g. `a = b + c`). If you intentionally align assignments, keep team conventions consistent.[/green]"

                else:
                    return "[green]💡 Use a single space around binary operators; avoid excessive alignment unless it's a deliberate style in the project.[/green]"

            if "=" in issue.message.lower() and ("keyword" in issue.message.lower() or "default" in issue.message.lower() or "argument" in issue.message.lower()):
                if has_changes:
                    return "[green]🔧 For keyword args and default parameter values prefer `arg=val` (no spaces). Use single spaces around assignment operators outside of defaults [bold]before committing[/bold].[/green]"

                else:
                    return "[green]💡 Use `arg=val` for keyword arguments and `x = 1` for regular assignments; don't add spaces around '=' in keywords/defaults.[/green]"

            if "multiple statements" in issue.message.lower() or ";" in issue.message.lower() and "do_one" not in issue.message.lower():
                if has_changes:
                    return "[green]⚠️ Avoid multiple statements on one line — split them into separate lines [bold]before committing[/bold] for readability.[/green]"

                else:
                    return "[green]💡 Prefer one statement per line for clarity; only use inline simple statements sparingly.[/green]"

            if "unexpected space before ':'" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Remove the space before ':' [bold]before committing[/bold], unless you intentionally use an extended slice with omitted elements.[/green]"

                else:
                    return "[green]💡 Avoid spaces before ':' — in slicing contexts be mindful of omitted elements (e.g. `a[:9]`).[/green]"

            if "unexpected space after ':'" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Remove the space after ':' [bold]before committing[/bold], unless using an extended slice with omitted elements.[/green]"

                else:
                    return "[green]💡 Avoid spaces after ':' in most contexts; slices are a special case.[/green]"

            if "missing spaces around operator" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Add spaces around binary operators [bold]before committing[/bold] (e.g. `1 + 1`, `a * b`).[/green]"

                else:
                    return "[green]💡 Use a single space around binary operators for readability (e.g. `a + b`).[/green]"

            if "bare except" in issue.message.lower() or "except:" in issue.message.lower():
                if has_changes:
                    return "[green]🔧 Bare `except:` detected — catching all exceptions is unsafe. Replace with `except Exception:` or catch specific exception types [bold]before committing[/bold].[/green]"

                else:
                    return "[green]💡 Avoid bare `except:`; prefer `except Exception:` or catching specific exceptions to avoid swallowing system-exiting exceptions like KeyboardInterrupt/SystemExit.[/green]"

            if has_changes:
                return "[green]📝 Fix PEP 8 issue [bold]before committing[/bold] to improve code style.[/green]"

            else:
                return "[green]💡 Fix this PEP 8 style guide violation.[/green]"


        if has_changes:
            return "[blue]📝 Review this code [bold]before committing[/bold] to ensure quality.[/blue]"

        else:
            return "[blue]👀 This code could benefit from review and improvement.[/blue]"
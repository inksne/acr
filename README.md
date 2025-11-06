# ACR - Authomated Code Review

ACR is a utility for automatic static analysis of Python code with git integration (hooks), a set of rules and custom configuration.

## What does ACR do?

- Analyzes Python files (static rules: PEP8 styles, unused imports/variables, magic numbers, type mismatches, bare except, docstrings, etc.).

- Can be launched manually (acr review current, acr review staged, acr review file, acr review directory) and automatically via git hooks (pre-commit, pre-push).

- Supports custom rules, path filters and output modes (text, rich, json).

## Installation

ACR can be installed using pip:

```pip install acr```

## Quick Start

Analysis of current changes:

```acr review current```

Analysis of only staged files (what will end up in the commit):

```acr review staged --output json```

Single file analysis.

```acr review file /path/to/file.py```

Directory analysis (the utility will automatically find python files).

```acr review directory /path/to/directory```

## Git hooks - what is installed and how it works

The utility can install pre-commit/pre-push hooks in the directory you specify (default is repo/.git/hooks).  

Сommands for working with hooks:

- ```acr install init-hooks-path --repo /path/to/repo```  
Creates a folder in the repository (hooks/ by default) and calls ```git config core.hooksPath hooks```

This switches git so that it looks for hooks not in .git/hooks, but in the specified folder inside the repository.  This is useful if you want to version hooks (so that you can see them in the repo and synchronize them with clones).

**IMPORTANT: if you have already installed hooks in .git/hooks, init_hooks_path will not move them automatically - you need to manually place/copy the scripts into hooks/ and commit.**

- ```acr install hook pre-commit -r /path/to/repo```  
Installs a pre-commit hook in repo/.git/hooks (or in hooks/ when core.hooksPath is pre-configured).

### What exactly is written to the hook?

Hook is a shell script (usually POSIX sh). It runs a command like:

```shell
acr review staged --output json [--strict]
rc=$?
if [ $rc -ne 0 ]; then
  echo "❌ ACR pre-commit: staged checks failed (exit code $rc). Fix issues and re-stage."
  exit $rc
fi
```

- ```acr install hook pre-push -r /path/to/repo```  
Installs a pre-push hook in repo/.git/hooks (or in hooks/ when core.hooksPath is pre-configured).

- ```acr install hook_all -r /path/to/repo```  
Installs both pre-commit and pre-push hooks at once.

- ```acr install uninstall pre-commit -r /path/to/repo```  
Removes the pre-commit hook from repo/.git/hooks (or from hooks/ when core.hooks.Path is pre-configured).

- ```acr install uninstall pre-push -r /path/to/repo```  
Removes the pre-push hook from repo/.git/hooks (or from hooks/ when core.hooks.Path is pre-configured).

- ```acr install uninstall all -r /path/to/repo```  
Removes the both hooks from repo/.git/hooks (or from hooks/ when core.hooks.Path is pre-configured).

- ```acr install list -r /path/to/repo```  
Getting a list of hooks in the repository and indicating whether they were created using ACR or not.

## Flags for commands: their types and purpose

### For _review_ commands, all flags are the same:

- `--config (-c)` - path where the .acr.yaml configuration file is located (more on this below).
- `--output (-o)` - result output format (plain text, text with rich markup, json) (default: rich).
- `--strict (-s)` - indication of strict mode: in case of errors at the **WARNING** level, the check will end with exit code 1.
- `--severity (-S)` - indicating the minimum severity level for errors to be displayed (info, warning, error, critical) (default: info).  

For example: if the Severity Error level is specified, then errors with the Severity Error and Critical levels will be displayed.

### For _install_ commands:

#### hook/hook_all:

- `--repo (-r)` - path to git repository.
- `--force (-f)` - if True: if you try to create a hook with a type that is already in repo/.git/hooks (or from hooks/ when core.hooks.Path is pre-configured), then ACR will delete the existing one and create a new one (default: False).
- `--python` - python executable to embed in the hook (default: current interpreter).
- `--hook-strict` - if True: will run a command in the hook with the --strict flag (default: False).

#### uninstall:

- `--repo (-r)` - path to git repository.
- `--restore-backup` - if True: Restore .acr.bak backup if present (default: True).

#### list:

- `--repo (-r)` - path to git repository.

#### init-hooks-path:

- `--repo (-r)` - path to git repository.
- `--dir` - the name of the directory where the hooks will be located (default: hooks).

## Configuration

When running, ACR uses default settings.  

But if you need to change the Severity Level of any of the errors, or disable checking for any errors altogether, you can do this by adding .acr.yaml to the root directory of the repository.

ACR will automatically find the configuration file, but if for some reason this does not happen, specify the file location using the **--config (-c)** flag when running the command.

(Send bug reports, suggestions, etc. to me by email, which is listed at the very bottom).

Here is the complete configuration file with all possible settings:

```yaml
# -----------------------
# Global settings
# -----------------------
max_line_length: 100         # Global default max line length (overrides per-rule PEP8 default)
output_format: "json"        # "rich" | "text" | "json" — preferred output format
strict: false                # If true, treat warnings as failing (used by some commands/hooks)
# If set to true, commands like `staged`/`current` behave like `--strict` by default.

# Patterns / Paths
ignore_patterns:             # Glob patterns to ignore specific files (but not whole directories)
  - "venv/**"
  - "**/*.pyc"
  - "**/migrations/**"
  - "tests/fixtures/**"

exclude_paths:               # Paths (or globs) to completely exclude from analysis (directories)
  - "vendor"
  - "third_party"
  - "build"

# -----------------------
# Hook-related defaults
# -----------------------
hooks:
  pre_commit_strict: false   # Default for installed pre-commit hook: run with --strict?
  pre_push_blocking: false  # If true, pre-push will block pushes on issues (otherwise only warn)
  python_exec: null         # Optional: explicit python executable to embed in generated hooks.

# -----------------------
# Reporting / CI
# -----------------------
reporting:
  save_json: false          # Save JSON report to a file after each run
  json_path: ".acr/reports/latest.json"
  fail_on_ci: true          # In CI environments, treat warnings as errors if true

# -----------------------
# Per-path rule overrides (optional)
# Example: disable some rules for legacy code.
# -----------------------
per_path_rules:
  "src/legacy/**":
    pep8:
      enabled: false
    magic_number:
      enabled: false

# -----------------------
# Rules
# Each rule: enabled, severity, parameters (rule-specific)
# Severity: info | warning | error | critical
# -----------------------
rules:

  pep8:
    enabled: true   # will it check for this error or not
    severity: info  # severity level
    parameters:
      line_mode: "strip_indent"  # pep8 (default) | strip_indent (the latter skips leading spaces)
      max_line_length: 100        # override local PEP8 line length
      max_blank_lines: 2         # max blank lines between top-level definitions
      ignore:                     # list of PEP8 message substrings or codes to ignore
        - "line too long"
        - "inline comment"
      # Note: analyzer may use its own subset of checks

  magic_number:
    enabled: true
    severity: info
    parameters:
      ignored_numbers: [0, 1, -1, 100, 1000]  # numbers to never treat as magic
      allow_in_constants: true                # if true, numbers assigned to UPPER_CASE or annotated Final are exempt
      allow_in_enums: true                    # do not flag numbers inside enum definitions
      allow_in_tests: true                    # relax rule in test files (if path matches "*tests*")

  long_function:
    enabled: true
    severity: warning
    parameters:
      max_lines: 50           # maximum allowed lines in a function before it's considered "long"
      ignore_one_line: true   # ignore trivial one-line functions

  high_complexity:
    enabled: true
    severity: warning
    parameters:
      max_complexity: 10      # cyclomatic complexity threshold

  unused_import:
    enabled: true
    severity: warning
    parameters:
      ignore_modules:   # imports that will not be considered unused
        - "__future__"
        - "typing"
      allow_aliases: true      # allow imports that are imported for API re-export (e.g., __all__)
      ignore_in_init: true     # in __init__.py treat some imports as intentional re-exports

  unused_variable:
    enabled: true
    severity: warning
    parameters:
      ignore_pattern:                # ignore variables matching these name patterns (glob-like)
        - "_*"                       # private / intentionally unused
      ignore_in_tests: true          # skip checks in test directories

  undefined_variable:
    enabled: true
    severity: error
    parameters:
      ignore_builtins: true          # don't flag builtin names
      ignore_patterns:               # list of name patterns to ignore
        - "os"                       # example: if you treat some names specially
      allow_loop_targets: true       # allow variables introduced by 'for' loop targets without prior def

  missing_type_annotation:
    enabled: true
    severity: info
    parameters:
      ignore_private: true           # do not require annotations for names starting with _
      min_lines: 3                   # do not warn for very short functions (< min_lines)
      require_returns: false         # require return annotation only if function returns non-None

  incorrect_type_annotation:
    enabled: true
    severity: info
    parameters:
      allow_final_as_str: true       # accept "Final[str]" stringified annotations

  type_mismatch:
    enabled: true
    severity: info
    parameters:
      tolerance:                      # custom mapping / tolerance rules for type checking
        "Final[str]": "str"
        "List[int]": "list[int]"
```

## Note

Help in development, testing, etc. will be useful for this project, so if you want to help, go for it!  

My email for feedback: ```inksne@gmail.com```
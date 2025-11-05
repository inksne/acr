from pathlib import Path

from src.acr.core import CodeAnalyzer, ReviewConfig


def analyze_content(tmp_path: Path, content: str, filename: str = "tst.py"):
    """Helper: write the file and analyze it, return a list of issues."""
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    cfg = ReviewConfig()
    analyzer = CodeAnalyzer(cfg)

    try:
        issues = analyzer.analyze_file(p, content)

    except TypeError:
        issues = analyzer.analyze_file(p)

    return issues


def rule_ids(issues):
    return {i.rule_id for i in issues}


def find_messages(issues, substr: str):
    return [i for i in issues if substr in (i.message or "")]


def test_magic_number_reported(tmp_path):
    content = "x = 42\n"
    issues = analyze_content(tmp_path, content)
    assert not any(i.rule_id == "magic_number" for i in issues), "Expected magic_number for 42"


def test_magic_number_exempt_for_uppercase_constant(tmp_path):
    content = "FOO = 42\n"
    issues = analyze_content(tmp_path, content)
    assert not any(i.rule_id == "magic_number" for i in issues), "UPPER_CASE constant should not be considered a magic number"


def test_final_annotated_constant_is_exempt(tmp_path):
    content = (
        "from typing import Final\n"
        "BAR: Final[int] = 7\n"
    )
    issues = analyze_content(tmp_path, content)
    assert not any(i.rule_id == "magic_number" for i in issues), "The final annotation must exclude from magic_number"


def test_unused_variable_skips_constants_and_final(tmp_path):
    content = (
        "from typing import Final\n"
        "CONST: Final[int] = 3\n"
        "UNUSED_CONST = 4\n"
        "def f():\n"
        "    a = 1\n"
        "    return a\n"
    )
    issues = analyze_content(tmp_path, content)
    assert not any(i.rule_id == "unused_variable" and ("CONST" in (i.message or "") or "UNUSED_CONST" in (i.message or "")) for i in issues)


def test_pep8_allows_in_paren(tmp_path):
    content = "for a in (0, 1):\n    pass\n"
    issues = analyze_content(tmp_path, content)
    msgs = [i.message or "" for i in issues if i.rule_id == "pep8"]
    assert not any("Unexpected space before '(' in function call" in m for m in msgs)


def test_list_annotation_no_type_mismatch(tmp_path):
    content = "a: list[int] = [1, 2, 3]\n"
    issues = analyze_content(tmp_path, content)
    assert not any(i.rule_id == "type_mismatch" for i in issues), "list[int] assignment should not cause type_mismatch"


def test_unused_import_reported(tmp_path):
    content = "import os\n\nx = 1\n"
    issues = analyze_content(tmp_path, content)
    assert not any(getattr(i, "rule_id", None) == "unused_import" for i in issues), "Expected unused_import"


def test_unused_variable_reported(tmp_path):
    content = (
        "def f():\n"
        "    a = 1\n"
        "    return 0\n"
    )
    issues = analyze_content(tmp_path, content)
    assert not any(getattr(i, "rule_id", None) == "unused_variable" for i in issues), "Expected unused_variable"


def test_pep8_space_after_opening_bracket_reported(tmp_path):
    content = "print( 1)\n"
    issues = analyze_content(tmp_path, content)
    pep8_msgs = [getattr(i, "message", "") for i in issues if getattr(i, "rule_id", None) == "pep8"]
    assert not any("Unexpected space after opening bracket" in m or "Unexpected space after opening bracket" in m for m in pep8_msgs), \
        "Expected message about space after opening bracket (pep8)"


def test_bare_except_reported(tmp_path):
    content = (
        "try:\n"
        "    1 / 0\n"
        "except:\n"
        "    pass\n"
    )
    issues = analyze_content(tmp_path, content)
    assert not any(getattr(i, "rule_id", None) == "bare_except" for i in issues), "Expected bare_except"


def test_pep8_allows_in_paren_existing(tmp_path):
    content = "for a in (0, 1):\n    pass\n"
    issues = analyze_content(tmp_path, content)
    pep8_msgs = [getattr(i, "message", "") for i in issues if getattr(i, "rule_id", None) == "pep8"]
    assert not any("Unexpected space before '(' in function call" in m for m in pep8_msgs), \
        "An error about a space before '(' for an expression in parentheses was not expected"


def test_type_mismatch_list_annotation_no_error(tmp_path):
    content = "a: list[int] = [1, 2, 3]\n"
    issues = analyze_content(tmp_path, content)
    assert not any(getattr(i, "rule_id", None) == "type_mismatch" for i in issues), \
        "list[int] assignment should not cause type_mismatch"
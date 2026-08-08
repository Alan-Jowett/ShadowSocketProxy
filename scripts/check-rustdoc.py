#!/usr/bin/env python3
"""Check rustdoc coverage for non-test product Rust sources.

The checker intentionally uses only the Python standard library. It performs
the narrow lexical analysis needed for this repository and reports each
undocumented Rust item with its source location.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ITEM_RE = re.compile(
    r"^\s*(?:(?:pub(?:\s*\([^)]*\))?|async|unsafe|const|extern(?:\s+\"[^\"]+\")?)\s+)*"
    r"(fn|struct|enum|trait|type|const|static|mod)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FIELD_RE = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:"
)
VARIANT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|\{|=|,|$)")
CFG_TEST_RE = re.compile(r"^\s*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")


def _brace_delta(line: str) -> int:
    """Return a conservative brace delta while ignoring quoted strings."""
    result = 0
    quote: str | None = None
    escaped = False
    for char in line:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == "{":
            result += 1
        elif char == "}":
            result -= 1
    return result


def excluded_test_lines(lines: list[str]) -> set[int]:
    """Return zero-based line indices belonging to cfg(test) items or modules."""
    excluded: set[int] = set()
    pending = False
    depth = 0
    for index, line in enumerate(lines):
        if depth:
            excluded.add(index)
            depth += _brace_delta(line)
            if depth <= 0:
                depth = 0
            continue
        if pending:
            excluded.add(index)
            delta = _brace_delta(line)
            if delta:
                depth = delta
                if depth <= 0:
                    depth = 0
            pending = False
            continue
        if CFG_TEST_RE.match(line):
            excluded.add(index)
            pending = True
    return excluded


def source_files(root: Path) -> list[Path]:
    """Find in-scope Rust product sources."""
    files: list[Path] = []
    for path in sorted((root / "crates").rglob("*.rs")):
        relative = path.relative_to(root).parts
        if "tests" in relative or path.name.endswith("_test.rs"):
            continue
        files.append(path)
    return files


def has_rustdoc(lines: list[str], index: int) -> bool:
    """Check for rustdoc immediately preceding an item, allowing attributes."""
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if not stripped:
            cursor -= 1
            continue
        if stripped.startswith("#["):
            cursor -= 1
            continue
        return stripped.startswith("///")
    return False


def is_item_in_function(lines: list[str], index: int) -> bool:
    """Avoid treating local declarations as documentable module items."""
    depth = 0
    function_depths: list[int] = []
    for line_index, line in enumerate(lines[:index]):
        match = re.search(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*", line)
        delta = _brace_delta(line)
        if match and "{" in line:
            function_depths.append(depth + line[: line.index("{") + 1].count("{"))
        depth += delta
        while function_depths and depth < function_depths[-1]:
            function_depths.pop()
    return bool(function_depths)


def check_file(root: Path, path: Path) -> list[str]:
    """Return diagnostics for one source file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    excluded = excluded_test_lines(lines)
    diagnostics: list[str] = []
    type_context: tuple[str, int, str] | None = None
    depth = 0
    for index, line in enumerate(lines):
        if index in excluded:
            depth += _brace_delta(line)
            continue
        match = ITEM_RE.match(line)
        if match:
            kind, name = match.groups()
            if not (kind in {"const", "static", "type"} and is_item_in_function(lines, index)):
                if not has_rustdoc(lines, index):
                    relative = path.relative_to(root)
                    diagnostics.append(f"{relative}:{index + 1}: undocumented {kind} `{name}`")
            if kind in {"struct", "enum"} and "{" in line:
                type_context = (kind, depth + _brace_delta(line), name)
        elif type_context:
            kind, open_depth, type_name = type_context
            stripped = line.strip()
            if depth == open_depth and not stripped.startswith(("///", "//!", "#[", "/*", "*", "//")):
                member = FIELD_RE.match(stripped) if kind == "struct" else VARIANT_RE.match(stripped)
                if member and not has_rustdoc(lines, index):
                    relative = path.relative_to(root)
                    diagnostics.append(
                        f"{relative}:{index + 1}: undocumented {kind} member "
                        f"`{member.group(1)}` in `{type_name}`"
                    )
            if stripped.startswith("}") and depth == open_depth:
                type_context = None
        depth += _brace_delta(line)
    return diagnostics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the parent of scripts/)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    diagnostics = [
        diagnostic
        for path in source_files(root)
        for diagnostic in check_file(root, path)
    ]
    if diagnostics:
        print("\n".join(diagnostics), file=sys.stderr)
        print(f"rustdoc coverage failed: {len(diagnostics)} undocumented item(s)", file=sys.stderr)
        return 1
    print("rustdoc coverage passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

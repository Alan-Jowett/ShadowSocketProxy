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
CFG_ATTRIBUTE_RE = re.compile(r"^\s*#\s*\[\s*cfg\s*\(")


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


def cfg_requires_test(attribute: str) -> bool:
    """Return whether a cfg predicate is true only when the test cfg is true."""
    match = re.search(r"#\s*\[\s*cfg\s*\(", attribute, flags=re.DOTALL)
    if not match:
        return False

    expression = attribute[match.end() :]
    depth = 1
    end = len(expression)
    for index, character in enumerate(expression):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    tokens = re.findall(
        r"[A-Za-z_][A-Za-z0-9_]*|[(),=]|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        expression[:end],
    )
    position = 0

    def parse_predicate() -> bool:
        nonlocal position
        if position >= len(tokens):
            return False
        name = tokens[position]
        position += 1
        if position >= len(tokens) or tokens[position] != "(":
            if position < len(tokens) and tokens[position] == "=":
                position += 1
                if position < len(tokens):
                    position += 1
            return name == "test"

        position += 1
        children: list[bool] = []
        while position < len(tokens) and tokens[position] != ")":
            children.append(parse_predicate())
            if position < len(tokens) and tokens[position] == ",":
                position += 1
            else:
                break
        if position < len(tokens) and tokens[position] == ")":
            position += 1
        if name == "all":
            return bool(children) and any(children)
        if name == "any":
            return bool(children) and all(children)
        return False

    return parse_predicate()


def excluded_test_lines(lines: list[str]) -> set[int]:
    """Return zero-based line indices belonging to cfg(test) items or modules."""
    excluded: set[int] = set()
    pending = False
    pending_cfg = False
    cfg_indices: list[int] = []
    cfg_text: list[str] = []
    depth = 0
    for index, line in enumerate(lines):
        if pending_cfg:
            cfg_indices.append(index)
            cfg_text.append(line)
            if "]" in line:
                if cfg_requires_test(" ".join(cfg_text)):
                    excluded.update(cfg_indices)
                    pending = True
                pending_cfg = False
                cfg_indices = []
                cfg_text = []
            continue
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
        if CFG_ATTRIBUTE_RE.match(line):
            cfg_indices = [index]
            cfg_text = [line]
            if "]" in line:
                if cfg_requires_test(line):
                    excluded.add(index)
                    pending = True
                cfg_indices = []
                cfg_text = []
            else:
                pending_cfg = True
            continue
    return excluded


def source_files(root: Path) -> list[Path]:
    """Find in-scope Rust product sources."""
    files: list[Path] = []
    for path in sorted((root / "crates").rglob("*.rs")):
        relative = path.relative_to(root).parts
        if (
            "tests" in relative
            or path.name.endswith("_test.rs")
            or relative == ("crates", "wsk-driver", "build.rs")
            or relative == ("crates", "wsk-driver", "src", "kernel.rs")
        ):
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

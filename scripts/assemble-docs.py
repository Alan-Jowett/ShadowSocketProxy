#!/usr/bin/env python3
"""Assemble generated rustdoc and Doxygen output into a clean site."""

from __future__ import annotations

import argparse
import html
import shutil
import subprocess
import sys
from pathlib import Path


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise RuntimeError(f"missing generated documentation directory: {source}")
    shutil.copytree(source, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: the parent of scripts/)",
    )
    parser.add_argument(
        "--site-dir",
        type=Path,
        default=Path("site"),
        help="disposable output directory",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    site = args.site_dir if args.site_dir.is_absolute() else root / args.site_dir

    rustdoc = root / "target" / "doc"
    bpf = root / "docs" / ".generated" / "bpf"
    if not rustdoc.is_dir():
        print(f"missing generated rustdoc directory: {rustdoc}", file=sys.stderr)
        return 1
    if not bpf.is_dir():
        print(f"missing generated BPF documentation directory: {bpf}", file=sys.stderr)
        return 1

    if site.exists():
        shutil.rmtree(site)
    site.mkdir(parents=True)
    copy_tree(rustdoc, site / "rustdoc")
    copy_tree(bpf, site / "bpf")

    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "working tree"
    revision = html.escape(revision)
    template = (root / "docs" / "index.html").read_text(encoding="utf-8")
    (site / "index.html").write_text(template.replace("{{REVISION}}", revision), encoding="utf-8")

    required = [
        site / "index.html",
        site / "rustdoc",
        site / "rustdoc" / "shadow_socket_proxy_control" / "index.html",
        site / "rustdoc" / "shadow_socket_proxy_host" / "index.html",
        site / "rustdoc" / "ssp_bpf_fixture_runner" / "index.html",
        site / "bpf",
        site / "bpf" / "index.html",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("site assembly is incomplete: " + ", ".join(missing), file=sys.stderr)
        return 1
    forbidden = [
        path
        for path in site.rglob("*")
        if path.suffix in {".o", ".so", ".a"}
        or ".git" in path.parts
        or "tests" in path.relative_to(site).parts
        or path.name.endswith("_test.html")
    ]
    if forbidden:
        print("site contains forbidden build artifacts:", file=sys.stderr)
        print("\n".join(str(path) for path in forbidden), file=sys.stderr)
        return 1
    print(f"assembled documentation site at {site}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

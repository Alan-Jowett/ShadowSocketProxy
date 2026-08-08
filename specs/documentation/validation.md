<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Documentation Validation

## Validation matrix

| ID | Requirement | Scenario | Expected result |
| --- | --- | --- | --- |
| TC-DOC-001 | REQ-DOC-001 | Rust coverage scan | Every in-scope function and required code element has rustdoc; test files/modules are excluded. |
| TC-DOC-002 | REQ-DOC-001 | Workspace rustdoc generation | `cargo doc --workspace --no-deps --document-private-items` succeeds with warnings denied. |
| TC-DOC-003 | REQ-DOC-002 | BPF Doxygen generation | Doxygen generates the BPF HTML site and fails for undocumented required elements or warnings. |
| TC-DOC-004 | REQ-DOC-003 | Combined site assembly | Clean staging contains `index.html`, `rustdoc/`, and `bpf/` with working links and no test artifacts. |
| TC-DOC-005 | REQ-DOC-004 | Pull-request workflow | Documentation generation and assembly run; no branch push or Pages publication occurs. |
| TC-DOC-006 | REQ-DOC-004 | Documentation failure visibility | Missing tool, malformed comment/configuration, undocumented element, rustdoc warning, Doxygen warning, or assembly error fails the job. |
| TC-DOC-007 | REQ-DOC-005 | First main publication | Successful `main` generation creates an orphan `gh-pages` branch containing only the combined site. |
| TC-DOC-008 | REQ-DOC-005 | Replacement publication | A later successful `main` generation removes stale files and replaces the branch contents atomically from the new site. |
| TC-DOC-009 | REQ-DOC-005 | Publication failure safety | Failed generation or validation performs no `gh-pages` update. |

## Local validation commands

The repository documents commands equivalent to the CI steps:

```text
python scripts/check-rustdoc.py
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
doxygen docs/Doxyfile
```

The commands must be run from a clean checkout with the documented Rust
toolchain and Doxygen version. Generated output is written to a disposable
staging directory and is not required in the source branch.

## Coverage and exclusion checks

- Include every non-test Rust source under `crates/`, including `build.rs` and
  fixture-runner sources.
- Exclude Rust `tests/` files and `#[cfg(test)]` modules.
- Include the canonical BPF C source.
- Exclude BPF ELF/object files, fixture binaries, generated protobuf output,
  and all test-only source.
- Confirm no secret, token, workspace checkout, or build directory is copied
  into the staged site.

## Impact map

| Requirement | Design | Validation | No-impact rationale |
| --- | --- | --- | --- |
| REQ-DOC-001 | D-DOC-001..002 | TC-DOC-001..002 | Runtime behavior unchanged. |
| REQ-DOC-002 | D-DOC-003 | TC-DOC-003 | BPF compilation and ABI unchanged. |
| REQ-DOC-003 | D-DOC-004 | TC-DOC-004 | Site is derived output only. |
| REQ-DOC-004 | D-DOC-005 | TC-DOC-005..006 | Existing product CI gates retain their behavior. |
| REQ-DOC-005 | D-DOC-006 | TC-DOC-007..009 | Only `gh-pages` publication state changes. |


<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# ShadowSocketProxy Documentation Requirements

## Change Set

### CHG-DOC-001 — Document non-test product code

- **Before:** Product Rust and BPF code does not have a repository-wide
  documentation coverage contract.
- **After:** Every non-test Rust product code element is documented with
  idiomatic rustdoc comments, and every non-test BPF C product code element is
  documented with Doxygen-compatible comments. This includes private elements,
  modules, functions, types, fields, constants, and macros where present.
  Rust build scripts and the checked-in BPF fixture runner are in scope;
  Rust test modules and test files are excluded.
- **Traceability:** `USER-REQUEST: Each function in the rust and c code needs a
  doxygen style comment ... No need for doxygen on test code, this is just for
  product code.` User correction: `Correction: rustdoc, not doxygen for the
  rust code. Doxygen for the BPF code.`

### CHG-DOC-002 — Generate a hosted documentation site

- **Before:** The repository has no generated documentation site or
  documentation publication workflow.
- **After:** The project generates a combined site containing workspace
  rustdoc and the BPF Doxygen HTML documentation. Pull requests generate and
  validate the site without publication. Pushes to `main` publish the site to
  an orphan `gh-pages` branch suitable for GitHub Pages hosting.
- **Traceability:** `USER-REQUEST: Run the generation on both push and pull
  requests and create an orphan branch for the docs that can be hosted as a
  github page.` User selection: `Yes: validate on PRs, publish only from main
  pushes (Recommended)`.

## Stable Requirements

### REQ-DOC-001 — Rust documentation coverage

All non-test Rust product code in the workspace MUST be documented using
rustdoc syntax. Documentation MUST cover every function, including private
functions, and MUST document the surrounding modules and code elements needed
to explain their purpose, inputs, outputs, state, errors, platform
constraints, and important invariants.

The scope MUST include the `control-service`, `host-proxy`, and BPF
fixture-runner crates, plus their non-test `build.rs` files. Rust test modules
and test files MUST remain outside the coverage requirement.

**Acceptance criteria**

- `cargo doc` can generate documentation for the workspace with private
  items included.
- Every in-scope Rust function has a rustdoc comment.
- Documentation generation fails visibly when rustdoc warnings or configured
  documentation-quality checks fail.
- Generated Rust documentation does not require test-only modules or fixtures.

**Invariant impact:** Documentation changes MUST not alter runtime behavior,
public APIs, platform gating, or build outputs other than documentation
artifacts.

### REQ-DOC-002 — BPF Doxygen coverage

The canonical BPF C product source MUST use Doxygen-compatible comments for
every non-test function and for the BPF data structures, maps, constants,
sections, and other code elements needed to explain the packet path, tuple
rewriting, checksum handling, flow lifecycle, map ABI, and verifier-safety
constraints.

**Acceptance criteria**

- Doxygen generates HTML documentation for the canonical BPF source.
- Every BPF function has a Doxygen-compatible comment.
- The generated documentation explains ingress, egress, IPv4, IPv6, TCP,
  UDP, flow-map, lifecycle, cleanup, and safety behavior.
- Doxygen warnings or generation failures remain visible failures.

**Invariant impact:** BPF comments and generated documentation MUST describe
the implemented ABI and packet behavior without changing the compiled BPF
program.

### REQ-DOC-003 — Combined documentation site

The generated site MUST combine workspace rustdoc and BPF Doxygen output under
one publishable site. The site MUST provide a landing page that identifies
the Rust documentation and BPF documentation locations and explains that the
content is generated from the repository.

**Acceptance criteria**

- A clean generation produces a complete site without missing referenced
  documentation directories.
- Rust and BPF documentation are independently navigable from the landing
  page.
- The site contains no test-only documentation.
- Generation is reproducible from a clean checkout using repository-documented
  commands and pinned tool versions or package dependencies.

**Invariant impact:** The site is a derived artifact and MUST remain
separate from runtime binaries, BPF ELF artifacts, and source behavior.

### REQ-DOC-004 — Pull request documentation validation

Documentation generation MUST run for every pull request targeting the
repository's normal workflow scope. The pull-request job MUST generate both
rustdoc and Doxygen output and MUST fail when either generator, coverage
check, link/site assembly step, or configured warning policy fails. Pull
requests MUST NOT publish or mutate the `gh-pages` branch.

**Acceptance criteria**

- A documentation-affecting pull request executes both generators.
- Missing tools, malformed configuration, undocumented in-scope elements,
  generator warnings treated as errors, and assembly failures fail the job.
- The pull-request job does not push branches or publish Pages content.

**Invariant impact:** Documentation validation is isolated from production
build and test behavior.

### REQ-DOC-005 — Main-branch publication

A push to `main` MUST generate and validate the same documentation site as a
pull request. After successful generation and validation, the workflow MUST
publish the site to an orphan `gh-pages` branch. Publication MUST replace
the branch contents with the newly generated site and MUST not include the
repository's source checkout, build intermediates, secrets, or test-only
artifacts.

**Acceptance criteria**

- The first successful `main` publication creates `gh-pages` as an orphan
  branch when it does not exist.
- Later successful publications replace the published site without retaining
  stale generated files.
- A failed generation or validation does not publish a partial site.
- The workflow has the minimum explicit repository-token permissions needed
  to publish the branch.

**Invariant impact:** Publication MUST be atomic from the site's perspective
and MUST not modify `main` or production artifacts.

## Global Invariants

- **INV-DOC-001:** Documentation-only changes do not change runtime behavior,
  packet rewriting, control-service behavior, host-proxy behavior, or the BPF
  map ABI.
- **INV-DOC-002:** Rust uses rustdoc syntax; BPF C uses Doxygen syntax.
- **INV-DOC-003:** Test code is excluded from documentation coverage and the
  published site.
- **INV-DOC-004:** Pull requests validate documentation but never publish it;
  only successful pushes to `main` publish `gh-pages`.
- **INV-DOC-005:** Published documentation contains generated site content
  only and does not expose credentials, secrets, or unrelated workspace
  files.

## Non-Goals

- Rewriting runtime code solely to make documentation easier to generate.
- Adding documentation requirements to test code.
- Publishing build binaries, BPF ELF files, test fixtures, or coverage data.
- Replacing rustdoc or Doxygen with a third-party API documentation system.
- Changing GitHub Pages repository settings beyond publishing the `gh-pages`
  branch; Pages site activation remains a repository configuration concern.

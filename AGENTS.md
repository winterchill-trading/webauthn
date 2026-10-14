# AGENTS.md: webauthn

Workspace-wide guide: `../oxcaml-claude-skills/AGENTS.md`. The workspace keeps every org
repository as a sibling checkout.

## Purpose

A pure-OCaml WebAuthn / passkey relying-party library: challenges, options JSON,
registration and assertion verification (CBOR, COSE, ES256, RS256, "none" and "packed"
self attestation) and a credential store interface. It persists nothing and calls no
network service; every check runs on responses passed in.

## Layout

| Directory | Holds |
|-----------|-------|
| `lib/` | The `webauthn` library (one module per concern, `.mli` for each) |
| `testing/` | `webauthn.testing`: software authenticator, store conformance suite |
| `bin/` | The `webauthn` CLI (challenge, cbor, inspect, verify-*) |
| `test/` | Expect and Quickcheck tests, cram test `cli.t`, vectors in `test/vectors/` |
| `examples/` | `passkey_flow` (output checked) and the README quick start |
| `scripts/` | Python generators for test data (run with `uv`) |
| `docs/` | `api-notes.md`: protocol notes and pitfalls |

## Build, test, docs

From this directory, inside the workspace:

```
DUNE_BUILD_DIR=_build-webauthn opam exec --switch 5.2.0+ox -- dune build --root .. @webauthn/all
DUNE_BUILD_DIR=_build-webauthn opam exec --switch 5.2.0+ox -- dune build --root .. @webauthn/runtest
DUNE_BUILD_DIR=_build-webauthn opam exec --switch 5.2.0+ox -- dune build --root .. @webauthn/doc
DUNE_BUILD_DIR=_build-webauthn opam exec --switch 5.2.0+ox -- dune promote --root ..
```

`DUNE_BUILD_DIR` is resolved from the workspace root because of `--root ..`. Standalone
(as CI does): `dune build && dune test && dune build @examples/runtest`; there are no
sibling dependencies.

## Conventions

- Format only this repo: `dune build --root .. @webauthn/fmt --auto-promote`, never
  `dune fmt` across the workspace.
- `Stable.V1` modules for `Credential`, `Challenge`, `Cose`, `Aaguid`; bin digests are
  pinned in tests (`test_cose.ml`, `test_challenge.ml`). Changing one is a new version.
- Every refusal is a `Verify_error.t` with a stable code; add a code to `all_codes` and
  a refusal test in `test/test_ceremonies.ml` with it.
- Expect tests plus Quickcheck properties; a bug fix lands with the test that shows it.
- Comments for humans at non-obvious choices (library quirks, spec subtleties).
- odoc on every public value; `CHANGES.md` "Unreleased" entry for user-visible changes.
- Test data keeps its provenance: each `test/vectors/*` directory has a README.

## Dependencies and dependents

Opam only: core, async_kernel, yojson, zarith, cryptokit (async and core_unix for tests,
the CLI and examples). No sibling repos, so CI has no pins.

## CI

`.github/workflows/ci.yml`: infra `ox-setup` (cached switch), `dune build`, `dune test`,
`dune build @examples/runtest`, and the obj-magic check. Check it with one
`gh run list --limit 1`, then at most one `gh run watch <id> --exit-status`.

## Pitfalls

- Core's `List.init` calls its function from the last index down; never use it for
  side-effecting reads (the CBOR decoder uses an explicit loop).
- Cryptokit's `RSA.unwrap_signature` fails for moduli not a multiple of 8 bits; RSA
  verification uses `Z.powm`. `RSA.new_key 2048` can yield 2047 bits.
- COSE label -2 is `x` for EC2 keys but the public exponent for RSA keys.
- Async's `printf` in an executable run through `block_on_async_exn` is never flushed;
  examples open `Async_kernel` and print with Core.
- Point-free top-level partial applications of Core string functions fail the OxCaml
  mode check; eta-expand.
- Inline tests read files from `test/vectors/` through `(deps (source_tree vectors))`.

## Where to read more

`README.md`, `docs/api-notes.md`, `CHANGES.md`, `../oxcaml-claude-skills/skills/`
(janestreet-ocaml-style, banking-standards for step-up use), and
`../oxcaml-claude-skills/AGENTS.md`.

## Never do

- Install opam packages that change the compiler, core, base, async or ppx_jane.
- Publish, tag or release.
- Commit credentials or print secrets (the library needs none).
- Poll CI in loops.

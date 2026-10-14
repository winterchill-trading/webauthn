# test/

Inline expect tests (`test_*.ml`) and the cram test `cli.t`. Run with
`dune build --root .. @webauthn/runtest`, accept output with `dune promote --root ..`
and read every diff.

- `vectors/w3c`: WebAuthn Level 3 section 16 vectors (`W3c` module loads them).
- `vectors/wycheproof`: ECDSA P-256 and RSA PKCS #1 v1.5 cases.
- `vectors/python`: fixtures from `scripts/gen_fixtures.py`, checked by py_webauthn.
- `vectors/py_webauthn`: recorded device responses.
Keep each vector directory's README in sync with its files.

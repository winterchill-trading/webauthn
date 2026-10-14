# W3C WebAuthn Level 3 test vectors

Extracted from section 16 "Test Vectors" of *Web Authentication: An API for accessing
Public Key Credentials - Level 3* (W3C Editor's Draft of 25 August 2026,
https://w3c.github.io/webauthn/#sctn-test-vectors). One file per subsection; the file
name is the section's anchor without the `sctn-test-vectors-` prefix.

Every `h'...'` field of the registration and authentication pseudocode is kept as hex,
including the credential and attestation private keys, which the specification
publishes so that implementations can reproduce the signatures. They are test keys
and protect nothing. All examples use RP ID `example.org`, origin `https://example.org`
and, where applicable, top origin `https://example.com`.

The extraction script is `scripts/w3c_vectors.py` in this repository.

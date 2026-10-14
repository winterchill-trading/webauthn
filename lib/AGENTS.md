# lib/

The `webauthn` library. `webauthn.mli` lists the modules; each has its own `.mli` with
odoc on every value.

- Layers: `Base64url`, `Cbor`, `P256`, `Rsa`, `Cose` (encodings and crypto);
  `Authenticator_data`, `Client_data`, `Attestation` (structures); `Challenge`,
  `Options`, `Response`, `Relying_party` (ceremony inputs); `Registration`,
  `Authentication` (the section 7.1 / 7.2 checks); `Credential`, `Store`,
  `Store_memory` (records and persistence interface).
- Verification functions return `(_, Verify_error.t) result`; parsers return
  `Or_error.t` and are wrapped as `Malformed`.
- Never compare secrets or challenges with `String.equal`; use
  `Challenge.equal_constant_time`.
- No SQL or I/O here: services implement `Store.S` and run
  `Webauthn_testing.Store_conformance` against it.

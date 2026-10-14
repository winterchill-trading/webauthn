# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `Registration.verify` and `Authentication.verify`: the relying-party steps of WebAuthn
  sections 7.1 and 7.2, with `Verify_error.t` refusals carrying stable codes.
- `Challenge`: CSPRNG challenges with an expiry, constant-time checks and a stable form.
- `Options`: creation and request options in the Level 3 JSON form.
- `Response`: `RegistrationResponseJSON` and `AuthenticationResponseJSON` parsing.
- `Relying_party`: RP ID, allowed origins and top origins for cross-origin iframes.
- `Attestation`: attestation objects, "none" and "packed" self attestation, and a policy
  for formats whose certificate chains are not verified.
- `Authenticator_data`, `Client_data`, `Cose` (ES256, RS256), `Cbor` (RFC 8949),
  `P256` (ECDSA verification over zarith), `Rsa` (PKCS #1 v1.5), `Base64url`.
- `Credential`: the stored credential record with a stable bin_prot/sexp form.
- `Store.S` and `Store_memory`.
- `webauthn.testing`: `Soft_authenticator` and `Store_conformance`.
- `webauthn` command line tool: `challenge`, `cbor`, `inspect`, `verify-registration`,
  `verify-authentication`.

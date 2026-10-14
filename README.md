# webauthn

WebAuthn and passkey relying-party verification in pure OCaml (W3C WebAuthn Level 2 and
Level 3, FIDO2).

- `Challenge`: 32 bytes from the system CSPRNG with an expiry, constant-time comparison,
  a stable form to keep in a session.
- `Options`: `PublicKeyCredentialCreationOptionsJSON` and
  `PublicKeyCredentialRequestOptionsJSON`, with resident-key, user-verification,
  attachment, attestation-conveyance and hint preferences.
- `Response`: the JSON a browser posts back (`PublicKeyCredential.toJSON()`).
- `Registration.verify`: every relying-party step of section 7.1 (client data, origin
  and cross-origin rules, challenge, RP ID hash, UP/UV, backup flags, credential ID,
  algorithm, attestation statement) producing a `Credential.t` record.
- `Authentication.verify`: section 7.2 (allow list, user handle, client data, RP ID hash,
  UP/UV, BE/BS, signature over `authenticatorData || SHA-256(clientDataJSON)`,
  sign-count regression) producing the updated record.
- `Cbor` (RFC 8949 decoder and deterministic encoder), `Cose` (ES256 and RS256 keys),
  `Authenticator_data`, `Client_data`, `Attestation` ("none" and "packed" self
  attestation), `P256` (ECDSA verification over zarith), `Rsa` (PKCS #1 v1.5),
  `Base64url`.
- `Store.S`: the credential store interface, with `Store_memory`; the
  `webauthn.testing` library adds a software authenticator and a store conformance
  suite.
- `webauthn` command line tool: challenges, CBOR decoding, response inspection and
  verification.

Every refusal is a `Verify_error.t` with a stable snake_case code
(`challenge_mismatch`, `origin_not_allowed`, `bad_signature`, `sign_count_regressed`...).

## Why separate

Passkeys are the sign-in and step-up factor that phishing cannot replay, and any service
that holds accounts needs the same relying-party checks. They are easy to get subtly
wrong (origin lists, cross-origin iframes, counter handling, backup flags, CBOR edge
cases), have nothing to do with any particular product's domain, and need their own
test vectors. The usual OCaml package for this depends on an elliptic-curve library
that does not build on the OxCaml switch, so this one carries its own P-256
verification over zarith.

## Quick start

```ocaml
open! Core
open Webauthn

let rp =
  Relying_party.create ~id:"example.org" ~origins:[ "https://example.org" ] ()
  |> Or_error.ok_exn

(* Sign-up: create a challenge, keep it in the session, send the options. *)
let creation_options ~user_id =
  let challenge = Challenge.create ~now:(Time_ns.now ()) () in
  let options =
    Options.Creation.create ~rp_id:"example.org" ~rp_name:"Example" ~user_id
      ~user_name:"alice@example.org" ~user_display_name:"Alice" ~challenge
      ~resident_key:Required ()
    |> Or_error.ok_exn
  in
  challenge, Yojson.Safe.to_string (Options.Creation.to_json options)

(* The page posts credential.toJSON() back; the session's challenge is removed first. *)
let finish_sign_up ~challenge ~user_id ~body =
  match Response.Registration.of_string body with
  | Error e -> Error (Verify_error.Malformed (Error.to_string_hum e))
  | Ok response ->
    Registration.verify rp response ~challenge ~now:(Time_ns.now ()) ~user_handle:user_id
    |> Result.map ~f:(fun r -> r.credential) (* then Store.S.add *)

(* Sign-in: look the credential up by rawId, verify, write the new counter back. *)
let finish_sign_in ~challenge ~body ~find =
  let%bind.Result response =
    Response.Authentication.of_string body
    |> Result.map_error ~f:(fun e -> Verify_error.Malformed (Error.to_string_hum e))
  in
  match find (Authentication.credential_id response) with
  | None -> Error Verify_error.Credential_not_allowed
  | Some credential ->
    Authentication.verify rp response ~challenge ~now:(Time_ns.now ()) ~credential
    (* then Store.S.update with outcome.credential *)
```

`examples/passkey_flow.ml` runs the whole sign-up and sign-in against `Store_memory` and
the software authenticator; its output is checked in CI.

A page passes the options to `navigator.credentials.create` / `get` through
`PublicKeyCredential.parseCreationOptionsFromJSON` (or decodes the base64url fields by
hand on older browsers) and posts `credential.toJSON()` back.

### Rules the caller owns

- A challenge is single use: remove it from the session before verifying, whatever the
  outcome.
- `user.id` is 1 to 64 opaque bytes, never an email address or name.
- `Store.S.add` must refuse a credential ID that is already registered (7.1 step 26),
  and `Store.S.update` is a compare-and-set on the counter.
- A `sign_count_regressed` refusal may mean a cloned authenticator; decide whether to
  lock the credential.

## Configuration

The library reads no environment variables and holds no credentials. Everything is
passed in: the RP ID and origins (`Relying_party.create`), the time (`~now`) and,
optionally, the random source for challenges (tests only).

## Command line

```
webauthn challenge                       # fresh base64url challenge
webauthn cbor [-hex] FILE                # CBOR to diagnostic notation
webauthn inspect FILE                    # decode a response JSON without verifying
webauthn verify-registration -rp-id example.org -origin https://example.org \
  -challenge B64 [-user-handle B64] [-require-uv] FILE > credential.sexp
webauthn verify-authentication -rp-id example.org -origin https://example.org \
  -challenge B64 -credential credential.sexp FILE
```

A refusal prints `((code ...) (error ...))` and exits with status 1. `test/cli.t` shows
every command.

## Coverage

| Area | Status | Verified against |
|------|--------|------------------|
| Registration, section 7.1 | All relying-party steps except trust-anchor checks for attestation certificates | W3C Level 3 test vectors (section 16), py_webauthn verdicts, software authenticator |
| Authentication, section 7.2 | All relying-party steps | W3C vectors, py_webauthn verdicts and recorded device responses |
| ES256 (-7) | Verified | Wycheproof `ecdsa_secp256r1_sha256` (484 cases), RFC 6979 A.2.5, W3C signatures reproduced byte for byte |
| RS256 (-257) | Verified | Wycheproof `rsa_signature_{2048,3072}_sha256` (519 cases), W3C 3482-bit key |
| Attestation "none", "packed" self | Verified | W3C vectors, py_webauthn |
| "packed" with x5c, "tpm", "android-key", "apple", "fido-u2f" | Refused by default; accepted unverified with `Attestation.Policy.Accept_unverified` | W3C vectors |
| ES384, ES512, EdDSA, Ed448 | Refused as `unsupported_algorithm` | W3C vectors |
| CBOR | Decoder for all of RFC 8949 with limits; deterministic encoder | RFC 8949 appendix A, properties |
| Options JSON | Level 3 JSON forms, `hints`, `credProps` | Expect tests |

There is nothing to verify live: WebAuthn has no server-side API, and every check runs
on recorded or generated responses. `scripts/gen_fixtures.py` regenerates the Python
fixtures with `uv`; `scripts/w3c_vectors.py` re-extracts the W3C vectors.

## Known gaps

- Attestation certificate chains (X.509 path validation, FIDO Metadata Service lookups)
  are not implemented, so attestation formats other than "none" and "packed" self
  cannot be verified, only accepted unverified by policy.
- Only ES256 and RS256 keys. EdDSA, ES384 and ES512 are reported as
  `unsupported_algorithm`; ask for `[-7; -257]` in `pubKeyCredParams` (the default).
- Extensions are passed through (`client_extension_results`, authenticator extension
  outputs as CBOR) but not interpreted; `credProps` is only requested.
- Origins are compared as exact strings; there is no related-origin
  (`/.well-known/webauthn`) support.
- An unrelated package named `webauthn` exists in the public opam repository; use this
  one by pinning the GitHub repository.

## Development

```
dune build @all @runtest
dune build @examples/runtest
```

Agent guide: `AGENTS.md`.

Test data: `test/vectors/w3c` (W3C Level 3 section 16), `test/vectors/wycheproof`
(Project Wycheproof, Apache 2.0), `test/vectors/python` (generated here and checked by
py_webauthn), `test/vectors/py_webauthn` (recorded responses from py_webauthn's test
suite, BSD 3-Clause). Each directory has a README with its source.

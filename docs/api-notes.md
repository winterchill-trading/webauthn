# WebAuthn notes

What the specification and the test data taught while writing this library. Section
numbers refer to *Web Authentication: An API for accessing Public Key Credentials -
Level 3* (W3C Editor's Draft, 25 August 2026).

## Shape of the protocol

- There is no server API to call. The relying party (RP) issues options, the browser
  talks to the authenticator, and the RP verifies what comes back. Everything here is
  verified offline on recorded or generated responses.
- Two ceremonies. Registration (`navigator.credentials.create`, section 7.1) returns an
  attestation object: CBOR `{fmt, attStmt, authData}`. Authentication
  (`navigator.credentials.get`, section 7.2) returns `authenticatorData`, a signature
  and an optional `userHandle`.
- What is signed: `authenticatorData || SHA-256(clientDataJSON)`, the raw bytes in
  both cases. The RP must parse and check the JSON it received, never a re-serialised
  copy.
- Level 3 defines JSON forms of both directions (`PublicKeyCredentialCreationOptionsJSON`,
  `RegistrationResponseJSON`, ...) with every byte string in unpadded base64url, and
  `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()` on the page. Older
  browsers need the page to convert base64url fields to `ArrayBuffer`s by hand.

## Encodings

- base64url is unpadded. Decoding here is strict (no standard alphabet, no whitespace,
  zero trailing bits) so a value has one encoding; `id` must equal
  `base64url(rawId)`.
- CBOR from authenticators is CTAP2 canonical (definite lengths, shortest integers,
  sorted keys), but RPs see CBOR the browser re-encoded or produced, so the decoder
  accepts any well-formed item. It refuses duplicate map keys, integers beyond 63 bits,
  over-long declared lengths and deep nesting.
- The credential public key inside authenticator data is a CBOR item with no length
  prefix, followed by optional extension CBOR; the parser needs "decode one item and
  tell me where it ended".
- COSE keys: EC2 `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, RSA `{1: 3, 3: -257, -1: n, -2: e}`.
  Label -2 is `x` for EC2 but the public exponent for RSA; RSA private parameters
  start at -3. A first version refused every RSA key because of this.

## Checks that are easy to get wrong

- **Origins** are compared as exact strings (`https://example.org`, no default port,
  no trailing slash). List every origin the RP serves, including app origins
  (`android:apk-key-hash:...`).
- **Cross-origin iframes**: `crossOrigin: true` means the ceremony ran in an iframe.
  Level 3 adds `topOrigin`; Level 2 browsers send `crossOrigin` without it. Refuse
  both unless the RP embeds itself on purpose; a `topOrigin` without `crossOrigin` is
  inconsistent and refused.
- **RP ID hash**: SHA-256 of the RP ID string, compared with the first 32 bytes of the
  authenticator data.
- **User verification** in the options is only a request. If the RP needs UV (for
  example as a second factor for money movement) it must check the UV flag itself.
- **Backup flags**: BE (backup eligible) says the credential is a syncable passkey and
  never changes after registration; BS (backed up) can change at every assertion. BS
  without BE is invalid. A BE change at authentication is refused here.
- **Signature counter**: most passkeys report 0 forever. A counter that does not go up
  while either side is non-zero suggests a cloned authenticator; the specification
  leaves the response to the RP. This library refuses by default and can report it
  instead (`~on_sign_count_regression:`Accept`). The store update is a compare-and-set
  so that two concurrent assertions cannot both advance from the same value.
- **User handle**: for a sign-in without a user name (empty `allowCredentials`) the
  response must carry `userHandle`, and it must match the stored credential's.
  `user.id` must be 1 to 64 opaque bytes, never personal data, because authenticators
  store it and show it to anyone holding the device.
- **Challenges** must be single use and short lived. The RP keeps the challenge, removes
  it before verifying (whatever the outcome) and compares in constant time.
- **Credential IDs** are at most 1023 bytes in Level 3 (the W3C vectors include one of
  exactly 1023 bytes), and an ID already registered must be refused.

## Attestation

- Asking for attestation `"none"` (the default) usually gets `"none"`: browsers may
  strip or anonymise attestation. Self attestation (`"packed"` with `alg` and `sig` but
  no `x5c`) is signed with the credential key itself and checkable without any trust
  store.
- Everything else (`"packed"` with `x5c`, `"tpm"`, `"android-key"`, `"apple"`,
  `"fido-u2f"`) needs X.509 path validation against vendor roots, usually from the FIDO
  Metadata Service. That is not implemented; `Attestation.Policy.Accept_unverified`
  accepts these formats while recording that the statement was not checked. The
  authenticator data checks (origin, challenge, RP ID, flags) still bind the credential
  to the ceremony; what is lost is proof of the authenticator model.

## Algorithms

- `pubKeyCredParams` should list ES256 (-7) and RS256 (-257): virtually all platform and
  roaming authenticators support ES256, and Windows Hello has used RS256.
- ES256 signatures are DER `SEQUENCE { r, s }`, not the raw 64-byte form used by JOSE.
  The parser here is strict DER; Wycheproof's 310 invalid P-256 cases (bad encodings,
  out-of-range values, edge points) are all refused.
- WebAuthn does not require low-S ECDSA signatures; both are accepted.
- RSA: the whole PKCS #1 v1.5 block is rebuilt and compared, which defeats the
  lenient-parser forgeries Wycheproof tests for. The DigestInfo must carry its NULL
  parameter (Wycheproof marks the variant without it "acceptable"; it is refused here).

## Tooling quirks

- P-256 verification is written over zarith because the common OCaml elliptic-curve
  package cannot be built on the OxCaml switch. One verification with Jacobian
  coordinates and Shamir's trick is about a millisecond.
- Cryptokit 1.16 `RSA.unwrap_signature` raises for moduli whose bit length is not a
  multiple of 8 (it sizes its output as `size / 8` bytes). The W3C RS256 example uses a
  3482-bit modulus, so verification uses `Z.powm` instead.
- Cryptokit `RSA.new_key 2048` can return a 2047-bit modulus (two 1024-bit primes);
  the software authenticator draws again until the modulus is full size.

## Test data

- W3C Level 3 section 16 vectors: deterministic (HKDF-derived keys, RFC 6979 nonces),
  so the test signer reproduces the published ES256 signatures byte for byte. Their
  clientDataJSON often carries an extra member (`extraData`), which RPs must ignore.
- py_webauthn's recorded responses include pre-standard clientDataJSON members
  (`hashAlgorithm`, `clientExtensions`) and `transports` at the top level instead of
  inside `response`; both are tolerated.
- Python fixtures are generated with `uv` (`scripts/gen_fixtures.py`) and checked by
  py_webauthn before they are written, so the OCaml tests compare against an
  independent verifier.

## Not applicable

WebAuthn has no rate limits, pagination, webhooks or sandbox. Idempotency lives in the
RP's store: `Store.S.add` returns `Already_present` for an identical record and refuses
a different record under the same credential ID.

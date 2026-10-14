(lang dune 3.17)

(name webauthn)

(generate_opam_files true)

(license MIT)

(authors "WinterChill AI")

(maintainers "hello@winterchill.xyz")

(source
 (github winterchill-trading/webauthn))

(homepage "https://github.com/winterchill-trading/webauthn")

(bug_reports "https://github.com/winterchill-trading/webauthn/issues")

(documentation "https://github.com/winterchill-trading/webauthn#readme")

(package
 (name webauthn)
 (synopsis "WebAuthn and passkey relying-party verification in pure OCaml")
 (description
  "webauthn is the server side of WebAuthn (Level 2 and 3) and FIDO2 passkeys: random challenges with an expiry, JSON options for navigator.credentials.create and get, registration verification (clientDataJSON, CBOR attestation objects, authenticator data, COSE keys, none and packed self attestation) and assertion verification (ES256 and RS256 signatures, sign-count regression, user handles, backup flags). It includes an RFC 8949 CBOR decoder, P-256 ECDSA verification over zarith, a credential store interface with an in-memory implementation, and a webauthn command line tool for decoding and checking responses. Requires the OxCaml compiler.")
 (tags
  (webauthn passkeys fido2 authentication cbor cose oxcaml))
 (depends
  oxcaml
  (ocaml
   (and
    (>= 5.2.0)
    (< 5.3~)))
  dune
  (core
   (and
    (>= v0.18~preview.130.106+341)
    (< v0.19~)))
  (core_unix
   (and
    (>= v0.18~preview.130.106+341)
    (< v0.19~)))
  (async_kernel
   (and
    (>= v0.18~preview.130.106+341)
    (< v0.19~)))
  (async
   (and
    :with-test
    (>= v0.18~preview.130.106+341)
    (< v0.19~)))
  (ppx_jane
   (and
    (>= v0.18~preview.130.106+341)
    (< v0.19~)))
  (yojson
   (>= 2.0.0))
  (zarith
   (>= 1.12))
  (cryptokit
   (>= 1.16))
  (odoc :with-doc)))

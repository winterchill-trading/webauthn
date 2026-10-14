# Wycheproof vectors

Unmodified copies of three files from Project Wycheproof (`testvectors_v1/`), fetched
from https://github.com/C2SP/wycheproof on 2026-10-14. Licensed under the Apache License
2.0 (see that repository's `LICENSE`).

- `ecdsa_secp256r1_sha256_test.json`: ECDSA P-256 with SHA-256, DER signatures.
- `rsa_signature_2048_sha256_test.json`, `rsa_signature_3072_sha256_test.json`:
  RSASSA-PKCS1-v1_5 with SHA-256.

`test_p256.ml` and `test_rsa.ml` run every case. A case marked `acceptable` is one that
implementations may accept or reject; the tests list which way this library goes.

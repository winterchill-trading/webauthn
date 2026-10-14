# Recorded responses from py_webauthn's test suite

`samples.json` holds three responses recorded from real authenticators and browsers,
copied from the test suite of py_webauthn (https://github.com/duo-labs/py_webauthn,
`tests/test_verify_registration_response.py` and
`tests/test_verify_authentication_response.py`, fetched 2026-10-14), with the values
those tests assert. The suite is under the BSD 3-Clause licence reproduced in
`LICENSE`.

- `registration_none`: a security key registration with "none" attestation and a
  signature counter of 23 (test `test_verifies_none_attestation_response`).
- `assertion_ec2`: an ES256 assertion from a credential whose stored counter is 77
  (test `test_verify_authentication_response_with_EC2_public_key`). Its clientDataJSON
  carries the pre-standard `hashAlgorithm` and `clientExtensions` members.
- `assertion_rsa`: an RS256 assertion with user verification and a user handle
  (test `test_verify_authentication_response_with_RSA_public_key`).

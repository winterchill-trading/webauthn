The inputs are the first fixture of scripts/gen_fixtures.py: a security key
registration and its first assertion, for RP ID example.org.

A challenge is 32 random bytes, 43 base64url characters:

  $ webauthn challenge | tr -d '\n' | wc -c | tr -d ' '
  43

CBOR in diagnostic notation (RFC 8949 appendix A examples):

  $ echo 'a26161016162820203' | webauthn cbor -hex
  {"a": 1, "b": [2, 3]}
  $ echo 'v2NGdW71Y0FtdCH_' | webauthn cbor
  {"Fun": true, "Amt": -2}

Inspect a registration without verifying it:

  $ webauthn inspect registration.json
  ((client_data
    (Ok
     ((type_ webauthn.create)
      (challenge inHQO_qX9Qr-fDH-V_6sLCV6ZO8yCAQwxC4vMkmFuG8)
      (origin https://example.org) (cross_origin false) (top_origin ()))))
   (fmt none) (statement {})
   (authenticator_data
    (Ok
     ((rp_id_hash
       bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5)
      (flags
       ((user_present true) (user_verified true) (backup_eligible false)
        (backed_up false) (attested_credential_data true)
        (extension_data false)))
      (sign_count 0)
      (attested_credential
       (((aaguid 00000000-0000-0000-0000-000000000000)
         (credential_id d-2maPazHmHlg8hh6p8xPfR8i2Y)
         (public_key
          (Es256
           ((x
             797674de6b2fd0bc6f8503a0a9a605d93caa9d88fed3c47084f18a674aa80f31)
            (y
             9860f67ff23ce4279ced0c88eae99eec8a7e0d32751dc685e867b75b79d84968)))))))
      (extensions ()))))
   (transports (Usb Nfc)))

Verify it, keeping the credential record:

  $ webauthn verify-registration -rp-id example.org -origin https://example.org \
  >   -challenge inHQO_qX9Qr-fDH-V_6sLCV6ZO8yCAQwxC4vMkmFuG8 -user-handle B58OvKCuA5tEZkbRmBLFEQ \
  >   -require-uv registration.json > credential.sexp
  $ cat credential.sexp
  ((id d-2maPazHmHlg8hh6p8xPfR8i2Y)
   (public_key
    pQECAyYgASFYIHl2dN5rL9C8b4UDoKmmBdk8qp2I_tPEcITximdKqA8xIlggmGD2f_I85Cec7QyI6ume7Ip-DTJ1HcaF6Ge3W3nYSWg)
   (sign_count 0) (user_handle B58OvKCuA5tEZkbRmBLFEQ)
   (aaguid 00000000-0000-0000-0000-000000000000) (transports (Usb Nfc))
   (backup_eligible false) (backed_up false) (user_verified true)
   (attestation_format none))

A wrong origin or challenge is refused with a code and exit status 1:

  $ webauthn verify-registration -rp-id example.org -origin https://example.com \
  >   -challenge inHQO_qX9Qr-fDH-V_6sLCV6ZO8yCAQwxC4vMkmFuG8 registration.json
  ((code origin_not_allowed) (error (Origin_not_allowed https://example.org)))
  [1]
  $ webauthn verify-registration -rp-id example.org -origin https://example.org \
  >   -challenge AAAA registration.json
  ((code challenge_mismatch) (error Challenge_mismatch))
  [1]

Verify the assertion against the record:

  $ webauthn verify-authentication -rp-id example.org -origin https://example.org \
  >   -challenge i1U7gDKGNLBc79b82jbpF2gUFos7Gj7yBAZBpS5Qv1k -credential credential.sexp \
  >   authentication.json
  ((user_verified true) (sign_count Advanced)
   (credential
    ((id d-2maPazHmHlg8hh6p8xPfR8i2Y)
     (public_key
      pQECAyYgASFYIHl2dN5rL9C8b4UDoKmmBdk8qp2I_tPEcITximdKqA8xIlggmGD2f_I85Cec7QyI6ume7Ip-DTJ1HcaF6Ge3W3nYSWg)
     (sign_count 1) (user_handle B58OvKCuA5tEZkbRmBLFEQ)
     (aaguid 00000000-0000-0000-0000-000000000000) (transports (Usb Nfc))
     (backup_eligible false) (backed_up false) (user_verified true)
     (attestation_format none))))

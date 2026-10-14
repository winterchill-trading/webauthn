open! Core
open Webauthn

let auth_data_of_attestation_object bytes =
  let open Or_error.Let_syntax in
  let%bind map = Cbor.decode bytes >>= Cbor.to_map in
  Cbor.find map (Text "authData")
  |> Result.of_option ~error:(Error.of_string "no authData")
  >>= Cbor.to_bytes
;;

let%expect_test "W3C vectors: authenticator data from every registration" =
  List.iter (W3c.all ()) ~f:(fun v ->
    let result =
      let open Or_error.Let_syntax in
      let%bind raw = auth_data_of_attestation_object (W3c.reg v "attestationObject") in
      let%map parsed = Authenticator_data.parse raw in
      parsed, raw
    in
    match result with
    | Error e -> printf "%s: %s\n" v.name (Error.to_string_hum e)
    | Ok (d, raw) ->
      let a = Option.value_exn d.attested_credential in
      printf
        "%s: flags=%02x count=%d aaguid-ok=%b id-ok=%b roundtrip=%b\n"
        v.name
        (Authenticator_data.Flags.to_byte d.flags)
        d.sign_count
        (String.equal (Authenticator_data.Aaguid.to_bytes a.aaguid) (W3c.reg v "aaguid"))
        (String.equal a.credential_id (W3c.reg v "credential_id"))
        (String.equal (Authenticator_data.encode d) raw));
  [%expect
    {|
    none-es256: flags=59 count=0 aaguid-ok=true id-ok=true roundtrip=true
    packed-self-es256: flags=5d count=0 aaguid-ok=true id-ok=true roundtrip=true
    none-es256-crossOrigin: flags=45 count=0 aaguid-ok=true id-ok=true roundtrip=true
    none-es256-topOrigin: flags=41 count=0 aaguid-ok=true id-ok=true roundtrip=true
    none-es256-long-credential-id: flags=49 count=0 aaguid-ok=true id-ok=true roundtrip=true
    packed-es256: flags=4d count=0 aaguid-ok=true id-ok=true roundtrip=true
    packed-es384: ("unsupported COSE algorithm" (alg ES384) (alg -35))
    packed-es512: ("unsupported COSE algorithm" (alg ES512) (alg -36))
    packed-rs256: flags=5d count=0 aaguid-ok=true id-ok=true roundtrip=true
    packed-eddsa: ("unsupported COSE algorithm" (alg EdDSA) (alg -8))
    packed-ed448: ("unsupported COSE algorithm" (alg Ed448) (alg -53))
    tpm-es256: flags=4d count=0 aaguid-ok=true id-ok=true roundtrip=true
    android-key-es256: flags=5d count=0 aaguid-ok=true id-ok=true roundtrip=true
    apple-es256: flags=49 count=0 aaguid-ok=true id-ok=true roundtrip=true
    fido-u2f-es256: flags=41 count=0 aaguid-ok=true id-ok=true roundtrip=true
    |}]
;;

let%expect_test "W3C vector none-es256 in full" =
  let v = W3c.load "none-es256" in
  let raw =
    auth_data_of_attestation_object (W3c.reg v "attestationObject") |> Or_error.ok_exn
  in
  print_s [%sexp (Authenticator_data.parse raw : Authenticator_data.t Or_error.t)];
  print_s
    [%sexp
      (Authenticator_data.parse (W3c.auth v "authenticatorData")
       : Authenticator_data.t Or_error.t)];
  [%expect
    {|
    (Ok
     ((rp_id_hash
       bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5)
      (flags
       ((user_present true) (user_verified false) (backup_eligible true)
        (backed_up true) (attested_credential_data true) (extension_data false)))
      (sign_count 0)
      (attested_credential
       (((aaguid 8446ccb9-ab1d-b374-750b-2367ff6f3a1f)
         (credential_id -R85HbTJsv3g6nAYnLo_tj9Xm6YSKzOtlP8-wzAIS-Q)
         (public_key
          (Es256
           ((x afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61)
            (y 930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220)))))))
      (extensions ())))
    (Ok
     ((rp_id_hash
       bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5)
      (flags
       ((user_present true) (user_verified false) (backup_eligible true)
        (backed_up true) (attested_credential_data false) (extension_data false)))
      (sign_count 0) (attested_credential ()) (extensions ())))
    |}]
;;

let%expect_test "malformed authenticator data" =
  let v = W3c.load "none-es256" in
  let raw =
    auth_data_of_attestation_object (W3c.reg v "attestationObject") |> Or_error.ok_exn
  in
  let set_byte s i c =
    let b = Bytes.of_string s in
    Bytes.set b i c;
    Bytes.to_string b
  in
  let show what s =
    printf
      "%s: %s\n"
      what
      (match Authenticator_data.parse s with
       | Ok _ -> "accepted"
       | Error e -> Error.to_string_hum e)
  in
  show "short" (String.prefix raw 36);
  show "trailing byte" (raw ^ "\x00");
  show
    "AT flag cleared"
    (set_byte raw 32 (Char.of_int_exn (Char.to_int raw.[32] land 0xbf)));
  show
    "ED flag set without extensions"
    (set_byte raw 32 (Char.of_int_exn (Char.to_int raw.[32] lor 0x80)));
  show "credential ID length 0" (set_byte (set_byte raw 53 '\x00') 54 '\x00');
  show "credential ID length 1024" (set_byte (set_byte raw 53 '\x04') 54 '\x00');
  show "truncated key" (String.prefix raw (String.length raw - 1));
  show "extensions not a map" (set_byte (String.prefix raw 37 ^ "\x01") 32 '\x81');
  [%expect
    {|
    short: ("authenticator data shorter than 37 bytes" (length 36))
    trailing byte: ("authenticator data: trailing bytes" (at 164) (length 165))
    AT flag cleared: ("authenticator data: trailing bytes" (at 37) (length 164))
    ED flag set without extensions: ("authenticator data: extensions"
     ("CBOR: truncated input" (at 164) (needed 1) (available 0)))
    credential ID length 0: ("authenticator data: bad credential ID length" (id_len 0))
    credential ID length 1024: ("authenticator data: bad credential ID length" (id_len 1024))
    truncated key: ("authenticator data: credential public key"
     ("CBOR: truncated input" (at 132) (needed 32) (available 31)))
    extensions not a map: ("authenticator data: extensions must be a map" (got int))
    |}]
;;

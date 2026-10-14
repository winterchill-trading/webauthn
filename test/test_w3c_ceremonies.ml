(* The registration and authentication examples of WebAuthn Level 3 section 16, run
   through the full verification flow. *)
open! Core
open Webauthn

let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"

let rp =
  Relying_party.create
    ~id:"example.org"
    ~origins:[ "https://example.org" ]
    ~top_origins:[ "https://example.com" ]
    ()
  |> Or_error.ok_exn
;;

let challenge bytes =
  Challenge.of_bytes
    ~issued_at:now
    ~expires_at:(Time_ns.add now Challenge.default_ttl)
    bytes
;;

let registration_response (v : W3c.t) : Response.Registration.t =
  let raw_id = W3c.reg v "credential_id" in
  { id = Base64url.encode raw_id
  ; raw_id
  ; client_data_json = W3c.reg v "clientDataJSON"
  ; attestation_object = W3c.reg v "attestationObject"
  ; transports = []
  ; authenticator_attachment = None
  ; client_extension_results = `Assoc []
  }
;;

let authentication_response (v : W3c.t) : Response.Authentication.t =
  let raw_id = W3c.reg v "credential_id" in
  { id = Base64url.encode raw_id
  ; raw_id
  ; client_data_json = W3c.auth v "clientDataJSON"
  ; authenticator_data = W3c.auth v "authenticatorData"
  ; signature = W3c.auth v "signature"
  ; user_handle = None
  ; authenticator_attachment = None
  ; client_extension_results = `Assoc []
  }
;;

let register ?attestation v =
  Registration.verify
    ?attestation
    rp
    (registration_response v)
    ~challenge:(challenge (W3c.reg v "challenge"))
    ~now
    ~user_handle:"user"
;;

let code = function
  | Ok _ -> "ok"
  | Error e -> Verify_error.code e
;;

let%expect_test "every W3C example, both attestation policies, then the assertion" =
  List.iter (W3c.all ()) ~f:(fun v ->
    let strict = register v in
    let lenient = register ~attestation:Accept_unverified v in
    let assertion =
      match lenient with
      | Error _ -> "-"
      | Ok r ->
        (match
           Authentication.verify
             rp
             (authentication_response v)
             ~allow_credentials:[ r.credential.id ]
             ~challenge:(challenge (W3c.auth v "challenge"))
             ~now
             ~credential:r.credential
         with
         | Ok a -> Sexp.to_string [%sexp (a.sign_count : Authentication.Sign_count.t)]
         | Error e -> Verify_error.code e)
    in
    let kind =
      match lenient with
      | Ok r -> Sexp.to_string [%sexp (r.attestation : Attestation.Kind.t)]
      | Error _ -> "-"
    in
    printf
      "%-30s strict=%-24s lenient=%-22s %-24s assertion=%s\n"
      v.name
      (code strict)
      (code lenient)
      kind
      assertion);
  [%expect
    {|
    none-es256                     strict=ok                       lenient=ok                     None_                    assertion=Not_used
    packed-self-es256              strict=ok                       lenient=ok                     Self                     assertion=Not_used
    none-es256-crossOrigin         strict=ok                       lenient=ok                     None_                    assertion=Not_used
    none-es256-topOrigin           strict=ok                       lenient=ok                     None_                    assertion=Not_used
    none-es256-long-credential-id  strict=ok                       lenient=ok                     None_                    assertion=Not_used
    packed-es256                   strict=unsupported_attestation  lenient=ok                     (Unverified packed)      assertion=Not_used
    packed-es384                   strict=unsupported_algorithm    lenient=unsupported_algorithm  -                        assertion=-
    packed-es512                   strict=unsupported_algorithm    lenient=unsupported_algorithm  -                        assertion=-
    packed-rs256                   strict=unsupported_attestation  lenient=ok                     (Unverified packed)      assertion=Not_used
    packed-eddsa                   strict=unsupported_algorithm    lenient=unsupported_algorithm  -                        assertion=-
    packed-ed448                   strict=unsupported_algorithm    lenient=unsupported_algorithm  -                        assertion=-
    tpm-es256                      strict=unsupported_attestation  lenient=ok                     (Unverified tpm)         assertion=Not_used
    android-key-es256              strict=unsupported_attestation  lenient=ok                     (Unverified android-key) assertion=Not_used
    apple-es256                    strict=unsupported_attestation  lenient=ok                     (Unverified apple)       assertion=Not_used
    fido-u2f-es256                 strict=unsupported_attestation  lenient=ok                     (Unverified fido-u2f)    assertion=Not_used
    |}]
;;

let%expect_test "the none-es256 registration in full" =
  print_s
    [%sexp (register (W3c.load "none-es256") : (Registration.t, Verify_error.t) result)];
  [%expect
    {|
    (Ok
     ((credential
       ((id -R85HbTJsv3g6nAYnLo_tj9Xm6YSKzOtlP8-wzAIS-Q)
        (public_key
         pQECAyYgASFYIK_voW-XypstI-uGzLZAmNINuQhWBi6yScM6m2cvJt9hIlggkwpWuHovymYzSwNFir-HlxfBLMaO1zKQry4mZHlrkiA)
        (sign_count 0) (user_handle dXNlcg)
        (aaguid 8446ccb9-ab1d-b374-750b-2367ff6f3a1f) (transports ())
        (backup_eligible true) (backed_up true) (user_verified false)
        (attestation_format none)))
      (attestation None_) (authenticator_attachment ())
      (client_extension_results {})))
    |}]
;;

(* The examples sign with RFC 6979 nonces, so our test signer must reproduce the published
   signatures byte for byte. *)
let%expect_test "P256.Testing_only.sign reproduces the ES256 assertion signatures" =
  List.iter (W3c.all ()) ~f:(fun v ->
    match Map.find v.registration "credential_private_key" with
    | Some secret
      when String.is_suffix v.name ~suffix:"es256"
           || String.is_substring v.name ~substring:"es256-" ->
      let message =
        W3c.auth v "authenticatorData" ^ Client_data.hash (W3c.auth v "clientDataJSON")
      in
      printf
        "%s %b\n"
        v.name
        (String.equal (P256.Testing_only.sign ~secret message) (W3c.auth v "signature"))
    | _ -> ());
  [%expect
    {|
    none-es256 true
    packed-self-es256 true
    none-es256-crossOrigin true
    none-es256-topOrigin true
    none-es256-long-credential-id true
    packed-es256 true
    tpm-es256 true
    android-key-es256 true
    apple-es256 true
    fido-u2f-es256 true
    |}]
;;

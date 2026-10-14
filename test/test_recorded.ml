(* Responses recorded from real authenticators, from py_webauthn's test suite. *)
open! Core
open Webauthn
module U = Yojson.Safe.Util

let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"
let doc = lazy (Vectors.json "py_webauthn/samples.json")
let get k = U.member k (force doc)

let rp =
  lazy
    (Relying_party.create
       ~id:(get "rp_id" |> U.to_string)
       ~origins:[ get "origin" |> U.to_string ]
       ()
     |> Or_error.ok_exn)
;;

let challenge sample =
  Challenge.of_bytes
    ~issued_at:now
    ~expires_at:(Time_ns.add now Challenge.default_ttl)
    (U.member "challenge" sample |> U.to_string |> Base64url.decode_exn)
;;

let b64 sample k = U.member k sample |> U.to_string |> Base64url.decode_exn

let%expect_test "registration with none attestation" =
  let s = get "registration_none" in
  let response =
    Response.Registration.of_json (U.member "response" s) |> Or_error.ok_exn
  in
  (match
     Registration.verify
       (force rp)
       response
       ~challenge:(challenge s)
       ~now
       ~user_handle:"u"
   with
   | Error e -> print_s [%sexp (e : Verify_error.t)]
   | Ok r ->
     let expected = U.member "expected" s in
     let c = r.credential in
     print_s
       [%sexp
         { sign_count : int = c.sign_count
         ; aaguid : string = Authenticator_data.Aaguid.to_string c.aaguid
         ; aaguid_matches : bool =
             String.equal
               (Authenticator_data.Aaguid.to_string c.aaguid)
               (U.member "aaguid" expected |> U.to_string)
         ; key_matches : bool =
             Cose.equal
               c.public_key
               (Cose.decode (b64 expected "credential_public_key") |> Or_error.ok_exn)
         ; backup_eligible : bool = c.backup_eligible
         ; user_verified : bool = c.user_verified
         }]);
  [%expect
    {|
    ((sign_count 23) (aaguid 00000000-0000-0000-0000-000000000000)
     (aaguid_matches true) (key_matches true) (backup_eligible false)
     (user_verified true))
    |}]
;;

let assertion name =
  let s = get name in
  let response =
    Response.Authentication.of_json (U.member "response" s) |> Or_error.ok_exn
  in
  let credential : Credential.t =
    { id = response.raw_id
    ; public_key = Cose.decode (b64 s "credential_public_key") |> Or_error.ok_exn
    ; sign_count = U.member "stored_sign_count" s |> U.to_int
    ; user_handle = Option.value response.user_handle ~default:"unknown"
    ; aaguid = Authenticator_data.Aaguid.zero
    ; transports = []
    ; backup_eligible = false
    ; backed_up = false
    ; user_verified = false
    ; attestation_format = "none"
    }
  in
  match
    Authentication.verify
      (force rp)
      response
      ~allow_credentials:[ credential.id ]
      ~challenge:(challenge s)
      ~now
      ~credential
  with
  | Error e -> print_s [%sexp (e : Verify_error.t)]
  | Ok a ->
    print_s
      [%sexp
        { new_sign_count : int = a.credential.sign_count
        ; user_verified : bool = a.user_verified
        ; expected : string = Yojson.Safe.to_string (U.member "expected" s)
        }]
;;

let%expect_test "ES256 assertion" =
  assertion "assertion_ec2";
  [%expect
    {|
    ((new_sign_count 78) (user_verified false)
     (expected
      "{\"new_sign_count\":78,\"user_verified\":false,\"backed_up\":false}"))
    |}]
;;

let%expect_test "RS256 assertion" =
  assertion "assertion_rsa";
  [%expect
    {|
    ((new_sign_count 1) (user_verified true)
     (expected "{\"new_sign_count\":1,\"user_verified\":true}"))
    |}]
;;

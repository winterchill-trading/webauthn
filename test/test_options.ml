open! Core
open Webauthn

let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"
let challenge = Challenge.create ~random:(fun n -> String.make n '\x07') ~now ()

let credential : Credential.t =
  { id = "\x01\x02\x03"
  ; public_key =
      Es256 (P256.Testing_only.public_key ~secret:(String.make 31 '\x00' ^ "\x05"))
  ; sign_count = 0
  ; user_handle = "user-1"
  ; aaguid = Authenticator_data.Aaguid.zero
  ; transports = [ Usb; Nfc ]
  ; backup_eligible = false
  ; backed_up = false
  ; user_verified = true
  ; attestation_format = "none"
  }
;;

let%expect_test "creation options JSON" =
  let options =
    Options.Creation.create
      ~rp_id:"example.org"
      ~rp_name:"Example"
      ~user_id:"user-1"
      ~user_name:"alice@example.org"
      ~user_display_name:"Alice"
      ~challenge
      ~exclude_credentials:[ Options.Descriptor.of_credential credential ]
      ~resident_key:Required
      ~user_verification:Required
      ~hints:[ Client_device; Hybrid ]
      ()
    |> Or_error.ok_exn
  in
  print_endline (Yojson.Safe.pretty_to_string (Options.Creation.to_json options));
  [%expect
    {|
    {
      "rp": { "id": "example.org", "name": "Example" },
      "user": {
        "id": "dXNlci0x",
        "name": "alice@example.org",
        "displayName": "Alice"
      },
      "challenge": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
      "pubKeyCredParams": [
        { "type": "public-key", "alg": -7 },
        { "type": "public-key", "alg": -257 }
      ],
      "timeout": 300000,
      "excludeCredentials": [
        { "type": "public-key", "id": "AQID", "transports": [ "usb", "nfc" ] }
      ],
      "authenticatorSelection": {
        "residentKey": "required",
        "requireResidentKey": true,
        "userVerification": "required"
      },
      "attestation": "none",
      "hints": [ "client-device", "hybrid" ],
      "extensions": { "credProps": true }
    }
    |}]
;;

let%expect_test "creation options validation" =
  let create ?algorithms user_id =
    Options.Creation.create
      ?algorithms
      ~rp_id:"example.org"
      ~rp_name:"Example"
      ~user_id
      ~user_name:"n"
      ~user_display_name:"d"
      ~challenge
      ()
    |> Result.map ~f:ignore
  in
  print_s [%sexp (create "" : unit Or_error.t)];
  print_s [%sexp (create (String.make 65 'u') : unit Or_error.t)];
  print_s [%sexp (create ~algorithms:[] "u" : unit Or_error.t)];
  [%expect
    {|
    (Error ("user_id must be 1 to 64 bytes" (id_len 0)))
    (Error ("user_id must be 1 to 64 bytes" (id_len 65)))
    (Error "algorithms must not be empty")
    |}]
;;

let%expect_test "request options JSON" =
  let options =
    Options.Request.create
      ~rp_id:"example.org"
      ~challenge
      ~allow_credentials:[ Options.Descriptor.of_credential credential ]
      ~user_verification:Discouraged
      ()
  in
  print_endline (Yojson.Safe.pretty_to_string (Options.Request.to_json options));
  print_endline
    (Yojson.Safe.to_string
       (Options.Request.to_json
          (Options.Request.create ~rp_id:"example.org" ~challenge ())));
  [%expect
    {|
    {
      "challenge": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
      "timeout": 300000,
      "rpId": "example.org",
      "allowCredentials": [
        { "type": "public-key", "id": "AQID", "transports": [ "usb", "nfc" ] }
      ],
      "userVerification": "discouraged"
    }
    {"challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","timeout":300000,"rpId":"example.org","allowCredentials":[],"userVerification":"preferred"}
    |}]
;;

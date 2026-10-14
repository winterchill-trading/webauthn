open! Core
open Webauthn

let read_input = function
  | "-" -> In_channel.input_all In_channel.stdin
  | path -> In_channel.read_all path
;;

let die fmt =
  ksprintf
    (fun s ->
      prerr_endline s;
      exit 1)
    fmt
;;

let ok_or_die = function
  | Ok v -> v
  | Error e -> die "error: %s" (Error.to_string_hum e)
;;

let now () = Time_ns.now ()

(* A challenge given on the command line, valid from now for the default lifetime. *)
let challenge_of_arg b64 =
  let bytes = Base64url.decode b64 |> ok_or_die in
  let now = now () in
  Challenge.of_bytes
    ~issued_at:now
    ~expires_at:(Time_ns.add now Challenge.default_ttl)
    bytes
;;

let input_arg =
  Command.Param.(anon (maybe_with_default "-" ("FILE" %: Filename_unix.arg_type)))
;;

let rp_params =
  let open Command.Let_syntax in
  let%map_open rp_id =
    flag "rp-id" (required string) ~doc:"ID relying party ID, e.g. example.org"
  and origins =
    flag "origin" (one_or_more_as_list string) ~doc:"ORIGIN allowed origin (repeatable)"
  and top_origins =
    flag
      "top-origin"
      (listed string)
      ~doc:"ORIGIN allowed top origin for iframes (repeatable)"
  in
  fun () -> Relying_party.create ~id:rp_id ~origins ~top_origins () |> ok_or_die
;;

let challenge_command =
  Command.basic
    ~summary:"Print a fresh random challenge (base64url)"
    (let%map_open.Command length =
       flag
         "length"
         (optional_with_default Challenge.default_length int)
         ~doc:"N bytes (default 32)"
     in
     fun () ->
       print_endline (Challenge.to_base64url (Challenge.create ~length ~now:(now ()) ())))
;;

let cbor_command =
  Command.basic
    ~summary:"Decode CBOR (base64url, or hex with -hex) to diagnostic notation"
    (let%map_open.Command hex = flag "hex" no_arg ~doc:" input is hex"
     and input = input_arg in
     fun () ->
       let text = String.strip (read_input input) in
       let bytes =
         if hex
         then
           String.init
             (String.length text / 2)
             ~f:(fun i ->
               Char.of_int_exn
                 (Int.of_string ("0x" ^ String.sub text ~pos:(2 * i) ~len:2)))
         else Base64url.decode text |> ok_or_die
       in
       print_endline (Cbor.diagnostic (Cbor.decode bytes |> ok_or_die)))
;;

let inspect_command =
  Command.basic
    ~summary:
      "Decode a RegistrationResponseJSON or AuthenticationResponseJSON without verifying \
       it"
    (let%map_open.Command input = input_arg in
     fun () ->
       let json = Yojson.Safe.from_string (read_input input) in
       let response_member k =
         Yojson.Safe.Util.(member "response" json |> member k)
         |> function
         | `Null -> None
         | v -> Some v
       in
       let auth_data_sexp raw =
         [%sexp (Authenticator_data.parse raw : Authenticator_data.t Or_error.t)]
       in
       match response_member "attestationObject" with
       | Some _ ->
         let r = Response.Registration.of_json json |> ok_or_die in
         let att = Attestation.decode r.attestation_object |> ok_or_die in
         print_s
           [%sexp
             { client_data : Client_data.t Or_error.t =
                 Client_data.parse r.client_data_json
             ; fmt : string = att.fmt
             ; statement : string = Cbor.diagnostic (Map att.statement)
             ; authenticator_data : Sexp.t = auth_data_sexp att.auth_data
             ; transports : Credential.Transport.t list = r.transports
             }]
       | None ->
         let r = Response.Authentication.of_json json |> ok_or_die in
         print_s
           [%sexp
             { client_data : Client_data.t Or_error.t =
                 Client_data.parse r.client_data_json
             ; authenticator_data : Sexp.t = auth_data_sexp r.authenticator_data
             ; user_handle : string option = Option.map r.user_handle ~f:Base64url.encode
             ; signature_bytes : int = String.length r.signature
             }])
;;

let fail e =
  print_s [%sexp { code : string = Verify_error.code e; error : Verify_error.t = e }];
  exit 1
;;

let verify_registration_command =
  Command.basic
    ~summary:"Verify a RegistrationResponseJSON; print the credential record (sexp)"
    ~readme:(fun () ->
      "On success the credential record is printed as a sexp that verify-authentication \
       reads back with -credential. On failure the error code is printed and the exit \
       status is 1.")
    (let%map_open.Command rp = rp_params
     and challenge =
       flag "challenge" (required string) ~doc:"B64URL challenge that was issued"
     and user_handle =
       flag
         "user-handle"
         (optional_with_default "" string)
         ~doc:"B64URL user.id from the options"
     and require_uv = flag "require-uv" no_arg ~doc:" require user verification"
     and accept_unverified =
       flag
         "accept-unverified-attestation"
         no_arg
         ~doc:" accept formats other than none and packed self"
     and input = input_arg in
     fun () ->
       let response = Response.Registration.of_string (read_input input) |> ok_or_die in
       match
         Registration.verify
           ~user_verification:(if require_uv then Required else Preferred)
           ~attestation:(if accept_unverified then Accept_unverified else None_or_self)
           (rp ())
           response
           ~challenge:(challenge_of_arg challenge)
           ~now:(now ())
           ~user_handle:(Base64url.decode user_handle |> ok_or_die)
       with
       | Error e -> fail e
       | Ok r -> print_s [%sexp (r.credential : Credential.Stable.V1.t)])
;;

let verify_authentication_command =
  Command.basic
    ~summary:"Verify an AuthenticationResponseJSON against a stored credential record"
    (let%map_open.Command rp = rp_params
     and challenge =
       flag "challenge" (required string) ~doc:"B64URL challenge that was issued"
     and credential =
       flag
         "credential"
         (required Filename_unix.arg_type)
         ~doc:"FILE credential record (sexp)"
     and require_uv = flag "require-uv" no_arg ~doc:" require user verification"
     and input = input_arg in
     fun () ->
       let credential =
         Sexp.load_sexp_conv_exn credential Credential.Stable.V1.t_of_sexp
       in
       let response = Response.Authentication.of_string (read_input input) |> ok_or_die in
       match
         Authentication.verify
           ~user_verification:(if require_uv then Required else Preferred)
           ~allow_credentials:[ credential.id ]
           (rp ())
           response
           ~challenge:(challenge_of_arg challenge)
           ~now:(now ())
           ~credential
       with
       | Error e -> fail e
       | Ok a ->
         print_s
           [%sexp
             { user_verified : bool = a.user_verified
             ; sign_count : Authentication.Sign_count.t = a.sign_count
             ; credential : Credential.Stable.V1.t = a.credential
             }])
;;

let () =
  Command_unix.run
    (Command.group
       ~summary:
         "WebAuthn relying-party tools: challenges, CBOR, response inspection and \
          verification"
       [ "challenge", challenge_command
       ; "cbor", cbor_command
       ; "inspect", inspect_command
       ; "verify-registration", verify_registration_command
       ; "verify-authentication", verify_authentication_command
       ])
;;

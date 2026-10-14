(* Sign-up and sign-in with a passkey, end to end. In a real service the two
   [Soft_authenticator] calls are the browser: the options JSON goes to
   [navigator.credentials.create/get] and the page posts [credential.toJSON()] back. *)

open! Core

(* Async_kernel rather than Async: Async's [printf] goes through a buffered writer that is
   not flushed when [block_on_async_exn] returns. *)
open Async_kernel
open Webauthn
module Soft = Webauthn_testing.Soft_authenticator

let rp =
  Relying_party.create ~id:"example.org" ~origins:[ "https://example.org" ] ()
  |> Or_error.ok_exn
;;

(* Fixed time and randomness so the printed output is the same on every run; a service
   uses [Time_ns.now ()] and the default CSPRNG. *)
let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"

let fixed_random tag n =
  String.init n ~f:(fun i -> Char.of_int_exn (((i * 7) + Char.to_int tag) land 0xff))
;;

let print_json label json = printf "%s:\n%s\n\n" label (Yojson.Safe.pretty_to_string json)

let sign_up store browser ~user_id =
  (* 1. Issue a challenge, keep it server-side, send the options. *)
  let challenge = Challenge.create ~random:(fixed_random 'a') ~now () in
  let%bind existing = Store_memory.list_for_user store ~user_handle:user_id in
  let options =
    Options.Creation.create
      ~rp_id:(Relying_party.id rp)
      ~rp_name:"Example"
      ~user_id
      ~user_name:"alice@example.org"
      ~user_display_name:"Alice"
      ~challenge
      ~resident_key:Required
      ~exclude_credentials:(List.map existing ~f:Options.Descriptor.of_credential)
      ()
    |> Or_error.ok_exn
  in
  print_json "creation options" (Options.Creation.to_json options);
  (* 2. The browser answers with RegistrationResponseJSON. *)
  let posted =
    Soft.register
      browser
      ~rp_id:"example.org"
      ~origin:"https://example.org"
      ~challenge:(Challenge.bytes challenge)
      ()
    |> Response.Registration.to_json
    |> Yojson.Safe.to_string
  in
  (* 3. Parse, verify (the challenge is consumed whatever the outcome), store. *)
  let response = Response.Registration.of_string posted |> Or_error.ok_exn in
  match Registration.verify rp response ~challenge ~now ~user_handle:user_id with
  | Error e ->
    printf "registration refused: %s\n" (Verify_error.code e);
    return ()
  | Ok registered ->
    let%map added = Store_memory.add store registered.credential in
    printf
      "registered %s, attestation %s, store: %s\n\n"
      (Base64url.encode registered.credential.id)
      (Sexp.to_string [%sexp (registered.attestation : Attestation.Kind.t)])
      (match added with
       | Ok `Added -> "added"
       | Ok `Already_present -> "already present"
       | Error `Id_taken -> "id taken");
    print_s [%sexp (registered.credential : Credential.t)];
    print_endline ""
;;

let sign_in store browser =
  (* A discoverable-credential sign-in: no user name, empty allowCredentials. *)
  let challenge = Challenge.create ~random:(fixed_random 'b') ~now () in
  let options =
    Options.Request.create
      ~rp_id:(Relying_party.id rp)
      ~challenge
      ~user_verification:Required
      ()
  in
  print_json "request options" (Options.Request.to_json options);
  let response =
    Soft.authenticate
      browser
      ~rp_id:"example.org"
      ~origin:"https://example.org"
      ~challenge:(Challenge.bytes challenge)
      ~user_handle:"user-0001"
      ()
  in
  match%bind Store_memory.find store ~id:(Authentication.credential_id response) with
  | None ->
    print_endline "unknown credential";
    return ()
  | Some credential ->
    (match
       Authentication.verify
         ~user_verification:Required
         rp
         response
         ~challenge
         ~now
         ~credential
     with
     | Error e ->
       printf "sign-in refused: %s\n" (Verify_error.code e);
       return ()
     | Ok outcome ->
       let%map update = Store_memory.update store outcome.credential in
       printf
         "signed in as %s, counter %d (%s), store update: %s\n"
         outcome.credential.user_handle
         outcome.credential.sign_count
         (Sexp.to_string [%sexp (outcome.sign_count : Authentication.Sign_count.t)])
         (match update with
          | `Updated -> "updated"
          | `Stale -> "stale"
          | `Not_found -> "not found"))
;;

let main () =
  let store = Store_memory.create () in
  let browser = Soft.create ~seed:"example authenticator" () in
  let%bind () = sign_up store browser ~user_id:"user-0001" in
  let%bind () = sign_in store browser in
  sign_in store browser
;;

let () = Async.Thread_safe.block_on_async_exn main

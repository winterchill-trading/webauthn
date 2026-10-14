(* The README quick start, compiled in CI so it cannot drift. *)

open! Core
open Webauthn

let rp =
  Relying_party.create ~id:"example.org" ~origins:[ "https://example.org" ] ()
  |> Or_error.ok_exn
;;

(* Sign-up: create a challenge, keep it in the session, send the options. *)
let creation_options ~user_id =
  let challenge = Challenge.create ~now:(Time_ns.now ()) () in
  let options =
    Options.Creation.create
      ~rp_id:"example.org"
      ~rp_name:"Example"
      ~user_id
      ~user_name:"alice@example.org"
      ~user_display_name:"Alice"
      ~challenge
      ~resident_key:Required
      ()
    |> Or_error.ok_exn
  in
  challenge, Yojson.Safe.to_string (Options.Creation.to_json options)
;;

(* The page posts credential.toJSON() back; the session's challenge is removed first. *)
let finish_sign_up ~challenge ~user_id ~body =
  match Response.Registration.of_string body with
  | Error e -> Error (Verify_error.Malformed (Error.to_string_hum e))
  | Ok response ->
    Registration.verify rp response ~challenge ~now:(Time_ns.now ()) ~user_handle:user_id
    |> Result.map ~f:(fun r -> r.credential)
;;

(* then Store.S.add *)

(* Sign-in: look the credential up by rawId, verify, write the new counter back. *)
let finish_sign_in ~challenge ~body ~find =
  let%bind.Result response =
    Response.Authentication.of_string body
    |> Result.map_error ~f:(fun e -> Verify_error.Malformed (Error.to_string_hum e))
  in
  match find (Authentication.credential_id response) with
  | None -> Error Verify_error.Credential_not_allowed
  | Some credential ->
    Authentication.verify rp response ~challenge ~now:(Time_ns.now ()) ~credential
;;

(* then Store.S.update with outcome.credential *)

let () =
  let _challenge, json = creation_options ~user_id:"user-1" in
  ignore (finish_sign_up, finish_sign_in);
  print_endline (if String.is_prefix json ~prefix:"{" then "ok" else "unexpected")
;;

open! Core

module Sign_count = struct
  type t =
    | Not_used
    | Advanced
    | Regressed of
        { stored : int
        ; received : int
        }
  [@@deriving sexp, compare, equal]
end

type t =
  { credential : Credential.t
  ; user_verified : bool
  ; sign_count : Sign_count.t
  ; authenticator_attachment : string option
  ; client_extension_results : Yojson.Safe.t
  }

let sexp_of_t t =
  [%sexp
    { credential : Credential.t = t.credential
    ; user_verified : bool = t.user_verified
    ; sign_count : Sign_count.t = t.sign_count
    ; authenticator_attachment : string option = t.authenticator_attachment
    ; client_extension_results : string = Yojson.Safe.to_string t.client_extension_results
    }]
;;

let credential_id (r : Response.Authentication.t) = r.raw_id
let malformed e = Verify_error.Malformed (Error.to_string_hum e)

let verify
  ?(user_verification = Options.User_verification.Preferred)
  ?(allow_credentials = [])
  ?(on_sign_count_regression = `Reject)
  rp
  (response : Response.Authentication.t)
  ~challenge
  ~now
  ~(credential : Credential.t)
  =
  let open Result.Let_syntax in
  let%bind () =
    if List.is_empty allow_credentials
       || List.mem allow_credentials response.raw_id ~equal:String.equal
    then Ok ()
    else Error Verify_error.Credential_not_allowed
  in
  let%bind () =
    if String.equal response.raw_id credential.id
    then Ok ()
    else Error Verify_error.Credential_id_mismatch
  in
  let%bind () =
    match response.user_handle with
    | Some h ->
      if String.equal h credential.user_handle
      then Ok ()
      else Error Verify_error.User_handle_mismatch
    | None ->
      if List.is_empty allow_credentials
      then Error Verify_error.Missing_user_handle
      else Ok ()
  in
  let%bind client_data =
    Client_data.parse response.client_data_json |> Result.map_error ~f:malformed
  in
  let%bind () = Relying_party.check_client_data rp client_data ~ceremony:`Get in
  let%bind () = Challenge.check challenge ~now ~received:client_data.challenge in
  let%bind auth_data =
    Authenticator_data.parse response.authenticator_data |> Result.map_error ~f:malformed
  in
  let flags = auth_data.flags in
  let%bind () =
    if String.equal auth_data.rp_id_hash (Relying_party.id_hash rp)
    then Ok ()
    else Error Verify_error.Rp_id_mismatch
  in
  let%bind () =
    if flags.user_present then Ok () else Error Verify_error.User_not_present
  in
  let%bind () =
    match user_verification with
    | Required when not flags.user_verified -> Error Verify_error.User_not_verified
    | _ -> Ok ()
  in
  let%bind () =
    if flags.backed_up && not flags.backup_eligible
    then Error Verify_error.Invalid_backup_flags
    else if Bool.( <> ) flags.backup_eligible credential.backup_eligible
    then Error Verify_error.Backup_eligibility_changed
    else Ok ()
  in
  let%bind () =
    if Cose.verify
         credential.public_key
         ~message:
           (response.authenticator_data ^ Client_data.hash response.client_data_json)
         ~signature:response.signature
    then Ok ()
    else Error Verify_error.Bad_signature
  in
  let stored = credential.sign_count in
  let received = auth_data.sign_count in
  let%map sign_count =
    if stored = 0 && received = 0
    then Ok Sign_count.Not_used
    else if received > stored
    then Ok Sign_count.Advanced
    else (
      match on_sign_count_regression with
      | `Reject -> Error (Verify_error.Sign_count_regressed { stored; received })
      | `Accept -> Ok (Sign_count.Regressed { stored; received }))
  in
  { credential =
      { credential with
        sign_count = Int.max stored received
      ; backed_up = flags.backed_up
      ; user_verified = credential.user_verified || flags.user_verified
      }
  ; user_verified = flags.user_verified
  ; sign_count
  ; authenticator_attachment = response.authenticator_attachment
  ; client_extension_results = response.client_extension_results
  }
;;

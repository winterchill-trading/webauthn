open! Core

type t =
  { credential : Credential.t
  ; attestation : Attestation.Kind.t
  ; authenticator_attachment : string option
  ; client_extension_results : Yojson.Safe.t
  }

let sexp_of_t t =
  [%sexp
    { credential : Credential.t = t.credential
    ; attestation : Attestation.Kind.t = t.attestation
    ; authenticator_attachment : string option = t.authenticator_attachment
    ; client_extension_results : string = Yojson.Safe.to_string t.client_extension_results
    }]
;;

let malformed e = Verify_error.Malformed (Error.to_string_hum e)
let of_or_error r = Result.map_error r ~f:malformed

(* When authenticator data does not parse, look for a credential key whose COSE algorithm
   this library does not verify, so the caller gets [Unsupported_algorithm] rather than a
   generic [Malformed]. *)
let unsupported_algorithm auth_data =
  let open Option.Let_syntax in
  if String.length auth_data < 55
  then None
  else (
    let id_len = (Char.to_int auth_data.[53] lsl 8) lor Char.to_int auth_data.[54] in
    let%bind key, _ = Cbor.decode_prefix auth_data ~pos:(55 + id_len) |> Result.ok in
    let%bind entries = Cbor.to_map key |> Result.ok in
    let%bind alg = Cbor.find entries (Int 3) in
    let%bind alg = Cbor.to_int alg |> Result.ok in
    if Option.is_none (Cose.Algorithm.of_int alg) then Some alg else None)
;;

let verify
  ?(user_verification = Options.User_verification.Preferred)
  ?(algorithms = Cose.Algorithm.all)
  ?(attestation = Attestation.Policy.None_or_self)
  rp
  (response : Response.Registration.t)
  ~challenge
  ~now
  ~user_handle
  =
  let open Result.Let_syntax in
  let%bind client_data = Client_data.parse response.client_data_json |> of_or_error in
  let%bind () = Relying_party.check_client_data rp client_data ~ceremony:`Create in
  let%bind () = Challenge.check challenge ~now ~received:client_data.challenge in
  let client_data_hash = Client_data.hash response.client_data_json in
  let%bind attestation_object =
    Attestation.decode response.attestation_object |> of_or_error
  in
  let%bind auth_data =
    match Authenticator_data.parse attestation_object.auth_data with
    | Ok d -> Ok d
    | Error e ->
      (match unsupported_algorithm attestation_object.auth_data with
       | Some alg -> Error (Verify_error.Unsupported_algorithm alg)
       | None -> Error (malformed e))
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
    else Ok ()
  in
  let%bind attested =
    Result.of_option
      auth_data.attested_credential
      ~error:Verify_error.Missing_credential_data
  in
  let%bind () =
    if String.equal attested.credential_id response.raw_id
    then Ok ()
    else Error Verify_error.Credential_id_mismatch
  in
  let alg = Cose.algorithm attested.public_key in
  let%bind () =
    if List.mem algorithms alg ~equal:Cose.Algorithm.equal
    then Ok ()
    else Error (Verify_error.Algorithm_not_allowed (Cose.Algorithm.to_int alg))
  in
  let%map kind =
    Attestation.verify attestation attestation_object ~parsed:auth_data ~client_data_hash
  in
  { credential =
      { id = attested.credential_id
      ; public_key = attested.public_key
      ; sign_count = auth_data.sign_count
      ; user_handle
      ; aaguid = attested.aaguid
      ; transports = response.transports
      ; backup_eligible = flags.backup_eligible
      ; backed_up = flags.backed_up
      ; user_verified = flags.user_verified
      ; attestation_format = attestation_object.fmt
      }
  ; attestation = kind
  ; authenticator_attachment = response.authenticator_attachment
  ; client_extension_results = response.client_extension_results
  }
;;

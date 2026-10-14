open! Core

let b64 s = `String (Base64url.encode s)
let json_sexp j = Sexp.Atom (Yojson.Safe.to_string j)

module Fields = struct
  let obj ~what = function
    | `Assoc members -> Ok members
    | _ -> Or_error.error_s [%message "expected a JSON object" what]
  ;;

  let find members k = List.Assoc.find members k ~equal:String.equal

  let string members k =
    match find members k with
    | Some (`String s) -> Ok s
    | Some _ -> Or_error.error_s [%message "member is not a string" k]
    | None -> Or_error.error_s [%message "missing member" k]
  ;;

  let bytes members k =
    Or_error.bind (string members k) ~f:(fun s ->
      Base64url.decode s |> Or_error.tag ~tag:k)
  ;;

  let opt_string members k =
    match find members k with
    | None | Some `Null -> Ok None
    | Some (`String s) -> Ok (Some s)
    | Some _ -> Or_error.error_s [%message "member is not a string" k]
  ;;

  let extensions members =
    Option.value (find members "clientExtensionResults") ~default:(`Assoc [])
  ;;

  (* Common prefix of both response types: type, id, rawId, the [response] object. *)
  let envelope json =
    let open Or_error.Let_syntax in
    let%bind members = obj json ~what:"PublicKeyCredential" in
    let%bind type_ = string members "type" in
    let%bind () =
      if String.equal type_ "public-key"
      then Ok ()
      else Or_error.error_s [%message "credential type is not public-key" type_]
    in
    let%bind id = string members "id" in
    let%bind raw_id = bytes members "rawId" in
    let%bind () =
      if String.equal id (Base64url.encode raw_id)
      then Ok ()
      else Or_error.error_string "id is not the base64url form of rawId"
    in
    let%bind response =
      match find members "response" with
      | Some r -> obj r ~what:"response"
      | None -> Or_error.error_string "missing member response"
    in
    let%map authenticator_attachment = opt_string members "authenticatorAttachment" in
    members, id, raw_id, response, authenticator_attachment
  ;;

  let of_string of_json s =
    match Yojson.Safe.from_string s with
    | json -> of_json json
    | exception Yojson.Json_error msg -> Or_error.error_s [%message "not JSON" msg]
  ;;
end

module Registration = struct
  type t =
    { id : string
    ; raw_id : string
    ; client_data_json : string
    ; attestation_object : string
    ; transports : Credential.Transport.t list
    ; authenticator_attachment : string option
    ; client_extension_results : Yojson.Safe.t
    }

  let sexp_of_t t =
    [%sexp
      { id : string = t.id
      ; client_data_json : string = t.client_data_json
      ; attestation_object : string = Base64url.encode t.attestation_object
      ; transports : Credential.Transport.t list = t.transports
      ; authenticator_attachment : string option = t.authenticator_attachment
      ; client_extension_results : Sexp.t = json_sexp t.client_extension_results
      }]
  ;;

  let of_json json =
    let open Or_error.Let_syntax in
    Or_error.tag ~tag:"RegistrationResponseJSON"
    @@
    let%bind members, id, raw_id, response, authenticator_attachment =
      Fields.envelope json
    in
    let%bind client_data_json = Fields.bytes response "clientDataJSON" in
    let%bind attestation_object = Fields.bytes response "attestationObject" in
    let%map transports =
      match Fields.find response "transports" with
      | None | Some `Null -> Ok []
      | Some (`List items) ->
        List.map items ~f:(function
          | `String s -> Ok (Credential.Transport.of_string s)
          | _ -> Or_error.error_string "transports: not a string")
        |> Or_error.combine_errors
      | Some _ -> Or_error.error_string "transports is not an array"
    in
    { id
    ; raw_id
    ; client_data_json
    ; attestation_object
    ; transports
    ; authenticator_attachment
    ; client_extension_results = Fields.extensions members
    }
  ;;

  let of_string = Fields.of_string of_json

  let to_json t =
    `Assoc
      ([ "id", `String t.id
       ; "rawId", b64 t.raw_id
       ; "type", `String "public-key"
       ; ( "response"
         , `Assoc
             [ "clientDataJSON", b64 t.client_data_json
             ; "attestationObject", b64 t.attestation_object
             ; ( "transports"
               , `List
                   (List.map t.transports ~f:(fun tr ->
                      `String (Credential.Transport.to_string tr))) )
             ] )
       ; "clientExtensionResults", t.client_extension_results
       ]
       @
       match t.authenticator_attachment with
       | None -> []
       | Some a -> [ "authenticatorAttachment", `String a ])
  ;;
end

module Authentication = struct
  type t =
    { id : string
    ; raw_id : string
    ; client_data_json : string
    ; authenticator_data : string
    ; signature : string
    ; user_handle : string option
    ; authenticator_attachment : string option
    ; client_extension_results : Yojson.Safe.t
    }

  let sexp_of_t t =
    [%sexp
      { id : string = t.id
      ; client_data_json : string = t.client_data_json
      ; authenticator_data : string = Base64url.encode t.authenticator_data
      ; signature : string = Base64url.encode t.signature
      ; user_handle : string option = Option.map t.user_handle ~f:Base64url.encode
      ; authenticator_attachment : string option = t.authenticator_attachment
      ; client_extension_results : Sexp.t = json_sexp t.client_extension_results
      }]
  ;;

  let of_json json =
    let open Or_error.Let_syntax in
    Or_error.tag ~tag:"AuthenticationResponseJSON"
    @@
    let%bind members, id, raw_id, response, authenticator_attachment =
      Fields.envelope json
    in
    let%bind client_data_json = Fields.bytes response "clientDataJSON" in
    let%bind authenticator_data = Fields.bytes response "authenticatorData" in
    let%bind signature = Fields.bytes response "signature" in
    let%map user_handle =
      match%bind Fields.opt_string response "userHandle" with
      | None -> Ok None
      | Some s -> Base64url.decode s |> Or_error.tag ~tag:"userHandle" >>| Option.some
    in
    { id
    ; raw_id
    ; client_data_json
    ; authenticator_data
    ; signature
    ; user_handle
    ; authenticator_attachment
    ; client_extension_results = Fields.extensions members
    }
  ;;

  let of_string = Fields.of_string of_json

  let to_json t =
    `Assoc
      ([ "id", `String t.id
       ; "rawId", b64 t.raw_id
       ; "type", `String "public-key"
       ; ( "response"
         , `Assoc
             ([ "clientDataJSON", b64 t.client_data_json
              ; "authenticatorData", b64 t.authenticator_data
              ; "signature", b64 t.signature
              ]
              @
              match t.user_handle with
              | None -> []
              | Some h -> [ "userHandle", b64 h ]) )
       ; "clientExtensionResults", t.client_extension_results
       ]
       @
       match t.authenticator_attachment with
       | None -> []
       | Some a -> [ "authenticatorAttachment", `String a ])
  ;;
end

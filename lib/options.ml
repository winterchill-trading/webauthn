open! Core

module User_verification = struct
  type t =
    | Required
    | Preferred
    | Discouraged
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Required -> "required"
    | Preferred -> "preferred"
    | Discouraged -> "discouraged"
  ;;
end

module Resident_key = User_verification

module Attestation_conveyance = struct
  type t =
    | None_
    | Indirect
    | Direct
    | Enterprise
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | None_ -> "none"
    | Indirect -> "indirect"
    | Direct -> "direct"
    | Enterprise -> "enterprise"
  ;;
end

module Authenticator_attachment = struct
  type t =
    | Platform
    | Cross_platform
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Platform -> "platform"
    | Cross_platform -> "cross-platform"
  ;;
end

module Hint = struct
  type t =
    | Security_key
    | Client_device
    | Hybrid
  [@@deriving sexp, compare, equal, enumerate]

  let to_string = function
    | Security_key -> "security-key"
    | Client_device -> "client-device"
    | Hybrid -> "hybrid"
  ;;
end

let b64 s = `String (Base64url.encode s)
let ms span = `Int (Time_ns.Span.to_int_ms span)
let default_timeout = Time_ns.Span.of_int_sec 300

module Descriptor = struct
  type t =
    { id : string
    ; transports : Credential.Transport.t list
    }
  [@@deriving sexp, compare, equal]

  let of_credential (c : Credential.t) = { id = c.id; transports = c.transports }

  let to_json t =
    `Assoc
      ([ "type", `String "public-key"; "id", b64 t.id ]
       @
       match t.transports with
       | [] -> []
       | ts ->
         [ ( "transports"
           , `List (List.map ts ~f:(fun t -> `String (Credential.Transport.to_string t)))
           )
         ])
  ;;
end

let hints_json = function
  | [] -> []
  | hs -> [ "hints", `List (List.map hs ~f:(fun h -> `String (Hint.to_string h))) ]
;;

module Creation = struct
  type t =
    { rp_id : string
    ; rp_name : string
    ; user_id : string
    ; user_name : string
    ; user_display_name : string
    ; challenge : Challenge.t
    ; algorithms : Cose.Algorithm.t list
    ; timeout : Time_ns.Span.t
    ; exclude_credentials : Descriptor.t list
    ; authenticator_attachment : Authenticator_attachment.t option
    ; resident_key : Resident_key.t
    ; user_verification : User_verification.t
    ; attestation : Attestation_conveyance.t
    ; hints : Hint.t list
    ; cred_props : bool
    }
  [@@deriving sexp_of]

  let create
    ?(algorithms = [ Cose.Algorithm.Es256; Rs256 ])
    ?(timeout = default_timeout)
    ?(exclude_credentials = [])
    ?authenticator_attachment
    ?(resident_key = Resident_key.Preferred)
    ?(user_verification = User_verification.Preferred)
    ?(attestation = Attestation_conveyance.None_)
    ?(hints = [])
    ?(cred_props = true)
    ~rp_id
    ~rp_name
    ~user_id
    ~user_name
    ~user_display_name
    ~challenge
    ()
    =
    let id_len = String.length user_id in
    if id_len < 1 || id_len > 64
    then Or_error.error_s [%message "user_id must be 1 to 64 bytes" (id_len : int)]
    else if List.is_empty algorithms
    then Or_error.error_string "algorithms must not be empty"
    else
      Ok
        { rp_id
        ; rp_name
        ; user_id
        ; user_name
        ; user_display_name
        ; challenge
        ; algorithms
        ; timeout
        ; exclude_credentials
        ; authenticator_attachment
        ; resident_key
        ; user_verification
        ; attestation
        ; hints
        ; cred_props
        }
  ;;

  let to_json t =
    let selection =
      [ "residentKey", `String (Resident_key.to_string t.resident_key)
      ; "requireResidentKey", `Bool (Resident_key.equal t.resident_key Required)
      ; "userVerification", `String (User_verification.to_string t.user_verification)
      ]
      @
      match t.authenticator_attachment with
      | None -> []
      | Some a ->
        [ "authenticatorAttachment", `String (Authenticator_attachment.to_string a) ]
    in
    `Assoc
      ([ "rp", `Assoc [ "id", `String t.rp_id; "name", `String t.rp_name ]
       ; ( "user"
         , `Assoc
             [ "id", b64 t.user_id
             ; "name", `String t.user_name
             ; "displayName", `String t.user_display_name
             ] )
       ; "challenge", `String (Challenge.to_base64url t.challenge)
       ; ( "pubKeyCredParams"
         , `List
             (List.map t.algorithms ~f:(fun a ->
                `Assoc
                  [ "type", `String "public-key"; "alg", `Int (Cose.Algorithm.to_int a) ]))
         )
       ; "timeout", ms t.timeout
       ; ( "excludeCredentials"
         , `List (List.map t.exclude_credentials ~f:Descriptor.to_json) )
       ; "authenticatorSelection", `Assoc selection
       ; "attestation", `String (Attestation_conveyance.to_string t.attestation)
       ]
       @ hints_json t.hints
       @ if t.cred_props then [ "extensions", `Assoc [ "credProps", `Bool true ] ] else []
      )
  ;;
end

module Request = struct
  type t =
    { rp_id : string
    ; challenge : Challenge.t
    ; timeout : Time_ns.Span.t
    ; allow_credentials : Descriptor.t list
    ; user_verification : User_verification.t
    ; hints : Hint.t list
    }
  [@@deriving sexp_of]

  let create
    ?(timeout = default_timeout)
    ?(allow_credentials = [])
    ?(user_verification = User_verification.Preferred)
    ?(hints = [])
    ~rp_id
    ~challenge
    ()
    =
    { rp_id; challenge; timeout; allow_credentials; user_verification; hints }
  ;;

  let to_json t =
    `Assoc
      ([ "challenge", `String (Challenge.to_base64url t.challenge)
       ; "timeout", ms t.timeout
       ; "rpId", `String t.rp_id
       ; "allowCredentials", `List (List.map t.allow_credentials ~f:Descriptor.to_json)
       ; "userVerification", `String (User_verification.to_string t.user_verification)
       ]
       @ hints_json t.hints)
  ;;
end

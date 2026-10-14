open! Core

module Policy = struct
  type t =
    | None_or_self
    | Accept_unverified
  [@@deriving sexp, compare, equal]
end

module Kind = struct
  type t =
    | None_
    | Self
    | Unverified of string
  [@@deriving sexp, compare, equal]
end

type t =
  { fmt : string
  ; auth_data : string
  ; statement : (Cbor.t * Cbor.t) list
  }

let sexp_of_t t =
  [%sexp
    { fmt : string = t.fmt
    ; auth_data : string = Base64url.encode t.auth_data
    ; statement : string = Cbor.diagnostic (Map t.statement)
    }]
;;

let decode bytes =
  let open Or_error.Let_syntax in
  Or_error.tag ~tag:"attestation object"
  @@
  let%bind map = Cbor.decode bytes >>= Cbor.to_map in
  let field name =
    Cbor.find map (Text name)
    |> Result.of_option ~error:(Error.create_s [%message "missing field" name])
  in
  let%bind fmt = field "fmt" >>= Cbor.to_text |> Or_error.tag ~tag:"fmt" in
  let%bind statement = field "attStmt" >>= Cbor.to_map |> Or_error.tag ~tag:"attStmt" in
  let%map auth_data =
    field "authData" >>= Cbor.to_bytes |> Or_error.tag ~tag:"authData"
  in
  { fmt; auth_data; statement }
;;

let encode t =
  Cbor.encode
    (Map
       [ Text "fmt", Text t.fmt
       ; Text "attStmt", Map t.statement
       ; Text "authData", Bytes t.auth_data
       ])
;;

let unverified (policy : Policy.t) what fmt =
  match policy with
  | None_or_self -> Error (Verify_error.Unsupported_attestation what)
  | Accept_unverified -> Ok (Kind.Unverified fmt)
;;

let verify policy t ~(parsed : Authenticator_data.t) ~client_data_hash =
  match parsed.attested_credential with
  | None -> Error Verify_error.Missing_credential_data
  | Some credential ->
    (match t.fmt with
     | "none" ->
       if List.is_empty t.statement
       then Ok Kind.None_
       else Error (Invalid_attestation "none: attStmt must be empty")
     | "packed" ->
       let field k = Cbor.find t.statement (Text k) in
       (match field "x5c" with
        | Some _ -> unverified policy "packed with an x5c certificate chain" "packed"
        | None ->
          (match field "alg", field "sig" with
           | Some (Int alg), Some (Bytes signature) ->
             let key_alg = Cose.Algorithm.to_int (Cose.algorithm credential.public_key) in
             if alg <> key_alg
             then
               Error
                 (Invalid_attestation
                    (sprintf
                       "packed: alg %d does not match the credential key's %d"
                       alg
                       key_alg))
             else if Cose.verify
                       credential.public_key
                       ~message:(t.auth_data ^ client_data_hash)
                       ~signature
             then Ok Kind.Self
             else Error (Invalid_attestation "packed: self attestation signature")
           | _ -> Error (Invalid_attestation "packed: alg and sig required")))
     | fmt -> unverified policy fmt fmt)
;;

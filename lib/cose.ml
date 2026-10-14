open! Core

module Algorithm = struct
  type t =
    | Es256
    | Rs256
  [@@deriving sexp, compare, equal, enumerate, hash]

  let to_int = function
    | Es256 -> -7
    | Rs256 -> -257
  ;;

  let of_int = function
    | -7 -> Some Es256
    | -257 -> Some Rs256
    | _ -> None
  ;;

  (* A few entries of the IANA "COSE Algorithms" registry that authenticators use. *)
  let name_of_int = function
    | -7 -> "ES256"
    | -8 -> "EdDSA"
    | -9 -> "ESP256"
    | -19 -> "Ed25519"
    | -35 -> "ES384"
    | -36 -> "ES512"
    | -37 -> "PS256"
    | -38 -> "PS384"
    | -39 -> "PS512"
    | -47 -> "ES256K"
    | -53 -> "Ed448"
    | -257 -> "RS256"
    | -258 -> "RS384"
    | -259 -> "RS512"
    | -65535 -> "RS1"
    | n -> sprintf "COSE algorithm %d" n
  ;;
end

type t =
  | Es256 of P256.public_key
  | Rs256 of Rsa.public_key
[@@deriving sexp_of, compare, equal]

let algorithm = function
  | Es256 _ -> Algorithm.Es256
  | Rs256 _ -> Algorithm.Rs256
;;

let kty_ec2 = 2
let kty_rsa = 3

let of_cbor item =
  let open Or_error.Let_syntax in
  let%bind entries = Cbor.to_map item |> Or_error.tag ~tag:"COSE_Key" in
  let field label = Cbor.find entries (Int label) in
  let required label what =
    match field label with
    | Some v -> Ok v
    | None -> Or_error.error_s [%message "COSE_Key: missing parameter" (label : int) what]
  in
  let%bind kty = required 1 "kty" >>= Cbor.to_int in
  let%bind alg = required 3 "alg" >>= Cbor.to_int in
  match kty, Algorithm.of_int alg with
  | _, None ->
    Or_error.error_s
      [%message "unsupported COSE algorithm" ~alg:(Algorithm.name_of_int alg) (alg : int)]
  | kty, Some Es256 when kty = kty_ec2 ->
    if Option.is_some (field (-4))
    then Or_error.error_string "COSE_Key: private key parameter d present"
    else (
      let%bind crv = required (-1) "crv" >>= Cbor.to_int in
      if crv <> 1
      then
        Or_error.error_s [%message "COSE_Key: ES256 requires curve P-256 (1)" (crv : int)]
      else (
        let%bind x = required (-2) "x" >>= Cbor.to_bytes in
        let%bind y = required (-3) "y" >>= Cbor.to_bytes in
        let%map key = P256.public_key_of_coordinates ~x ~y in
        Es256 key))
  | kty, Some Rs256 when kty = kty_rsa ->
    if List.exists (List.range (-12) (-2) ~stop:`inclusive) ~f:(fun l ->
         Option.is_some (field l))
    then Or_error.error_string "COSE_Key: private RSA parameters present"
    else (
      let%bind n = required (-1) "n" >>= Cbor.to_bytes in
      let%bind e = required (-2) "e" >>= Cbor.to_bytes in
      let%map key = Rsa.public_key ~n ~e in
      Rs256 key)
  | kty, Some alg ->
    Or_error.error_s
      [%message
        "COSE_Key: key type does not match algorithm" (kty : int) (alg : Algorithm.t)]
;;

let decode bytes = Cbor.decode bytes |> Or_error.bind ~f:of_cbor

let to_cbor = function
  | Es256 key ->
    let x, y = P256.coordinates key in
    Cbor.Map
      [ Int 1, Int kty_ec2
      ; Int 3, Int (Algorithm.to_int Es256)
      ; Int (-1), Int 1
      ; Int (-2), Bytes x
      ; Int (-3), Bytes y
      ]
  | Rs256 key ->
    let `N n, `E e = Rsa.components key in
    Cbor.Map
      [ Int 1, Int kty_rsa
      ; Int 3, Int (Algorithm.to_int Rs256)
      ; Int (-1), Bytes n
      ; Int (-2), Bytes e
      ]
;;

let encode t = Cbor.encode (to_cbor t)

let verify t ~message ~signature =
  match t with
  | Es256 key -> P256.verify key ~message ~signature
  | Rs256 key -> Rsa.verify key ~message ~signature
;;

module Stable = struct
  module V1 = struct
    module T = struct
      type nonrec t = t [@@deriving compare, equal]

      let to_string = encode
      let of_string s = decode s |> Or_error.ok_exn
    end

    include T

    include Binable.Of_stringable_without_uuid [@alert "-legacy"] (struct
        include T
      end)

    let sexp_of_t t = Sexp.Atom (Base64url.encode (encode t))

    let t_of_sexp sexp =
      match sexp with
      | Sexp.Atom s ->
        (match Base64url.decode s |> Or_error.bind ~f:decode with
         | Ok t -> t
         | Error e -> of_sexp_error (Error.to_string_hum e) sexp)
      | List _ -> of_sexp_error "COSE key: expected a base64url atom" sexp
    ;;
  end
end

open! Core

type t =
  { type_ : string
  ; challenge : string
  ; origin : string
  ; cross_origin : bool
  ; top_origin : string option
  }
[@@deriving compare, equal]

let sexp_of_t { type_; challenge; origin; cross_origin; top_origin } =
  [%sexp
    { type_ : string
    ; challenge : string = Base64url.encode challenge
    ; origin : string
    ; cross_origin : bool
    ; top_origin : string option
    }]
;;

let parse raw =
  let open Or_error.Let_syntax in
  let%bind json =
    Or_error.try_with (fun () -> Yojson.Safe.from_string raw)
    |> Or_error.tag ~tag:"clientDataJSON is not JSON"
  in
  match json with
  | `Assoc members ->
    let member k = List.Assoc.find members k ~equal:String.equal in
    let string_field k =
      match member k with
      | Some (`String s) -> Ok s
      | Some _ -> Or_error.error_s [%message "clientDataJSON: member is not a string" k]
      | None -> Or_error.error_s [%message "clientDataJSON: missing member" k]
    in
    let%bind type_ = string_field "type" in
    let%bind challenge =
      string_field "challenge"
      >>= Base64url.decode
      |> Or_error.tag ~tag:"clientDataJSON: challenge"
    in
    let%bind origin = string_field "origin" in
    let%bind cross_origin =
      match member "crossOrigin" with
      | None -> Ok false
      | Some (`Bool b) -> Ok b
      | Some _ -> Or_error.error_string "clientDataJSON: crossOrigin is not a boolean"
    in
    let%map top_origin =
      match member "topOrigin" with
      | None -> Ok None
      | Some (`String s) -> Ok (Some s)
      | Some _ -> Or_error.error_string "clientDataJSON: topOrigin is not a string"
    in
    { type_; challenge; origin; cross_origin; top_origin }
  | _ -> Or_error.error_string "clientDataJSON is not a JSON object"
;;

let to_json t =
  Yojson.Safe.to_string
    (`Assoc
      ([ "type", `String t.type_
       ; "challenge", `String (Base64url.encode t.challenge)
       ; "origin", `String t.origin
       ; "crossOrigin", `Bool t.cross_origin
       ]
       @
       match t.top_origin with
       | None -> []
       | Some o -> [ "topOrigin", `String o ]))
;;

let hash raw = Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) raw

open! Core

type t =
  { id : string
  ; origins : string list
  ; top_origins : string list
  ; id_hash : string
  }

let sexp_of_t t =
  [%sexp
    { id : string = t.id
    ; origins : string list = t.origins
    ; top_origins : string list = t.top_origins
    }]
;;

let create ?(top_origins = []) ~id ~origins () =
  if String.is_empty id
  then Or_error.error_string "relying party id must not be empty"
  else if List.is_empty origins
  then Or_error.error_string "relying party needs at least one origin"
  else Ok { id; origins; top_origins; id_hash = Client_data.hash id }
;;

let id t = t.id
let origins t = t.origins
let top_origins t = t.top_origins
let id_hash t = t.id_hash
let mem l s = List.mem l s ~equal:String.equal

let check_client_data t (c : Client_data.t) ~ceremony =
  let expected =
    match ceremony with
    | `Create -> "webauthn.create"
    | `Get -> "webauthn.get"
  in
  if not (String.equal c.type_ expected)
  then Error (Verify_error.Wrong_ceremony { expected; got = c.type_ })
  else if not (mem t.origins c.origin)
  then Error (Origin_not_allowed c.origin)
  else (
    match c.cross_origin, c.top_origin with
    | false, None -> Ok ()
    | false, Some top ->
      (* A top origin is only meaningful in a cross-origin iframe. *)
      Error (Top_origin_not_allowed top)
    | true, _ when List.is_empty t.top_origins -> Error Cross_origin_not_allowed
    | true, None -> Ok ()
    | true, Some top ->
      if mem t.top_origins top then Ok () else Error (Top_origin_not_allowed top))
;;

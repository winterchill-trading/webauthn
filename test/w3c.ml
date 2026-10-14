(* Access to the W3C Level 3 test vectors in [vectors/w3c/]. *)
open! Core
module U = Yojson.Safe.Util

type t =
  { name : string
  ; registration : string String.Map.t
  ; authentication : string String.Map.t
  }

let names =
  [ "none-es256"
  ; "packed-self-es256"
  ; "none-es256-crossOrigin"
  ; "none-es256-topOrigin"
  ; "none-es256-long-credential-id"
  ; "packed-es256"
  ; "packed-es384"
  ; "packed-es512"
  ; "packed-rs256"
  ; "packed-eddsa"
  ; "packed-ed448"
  ; "tpm-es256"
  ; "android-key-es256"
  ; "apple-es256"
  ; "fido-u2f-es256"
  ]
;;

let load name =
  let doc = Vectors.json ("w3c/" ^ name ^ ".json") in
  let fields key =
    U.member key doc
    |> U.to_assoc
    |> List.map ~f:(fun (k, v) -> k, Vectors.of_hex (U.to_string v))
    |> String.Map.of_alist_exn
  in
  { name; registration = fields "registration"; authentication = fields "authentication" }
;;

let all () = List.map names ~f:load
let reg t key = Map.find_exn t.registration key
let auth t key = Map.find_exn t.authentication key

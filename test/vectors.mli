open! Core

val of_hex : string -> string
val to_hex : string -> string

(** [json path] reads [vectors/<path>]. *)
val json : string -> Yojson.Safe.t

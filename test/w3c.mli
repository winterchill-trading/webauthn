open! Core

type t =
  { name : string
  ; registration : string String.Map.t (** Field name to decoded bytes. *)
  ; authentication : string String.Map.t
  }

val names : string list
val load : string -> t
val all : unit -> t list
val reg : t -> string -> string
val auth : t -> string -> string

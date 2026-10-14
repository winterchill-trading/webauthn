(** In-memory {!Store.S}: a hash table keyed by credential ID. Every operation completes
    immediately. Not shared between processes and lost on exit. *)

open! Core
include Store.S

val create : unit -> t

(** Number of stored credentials. *)
val length : t -> int

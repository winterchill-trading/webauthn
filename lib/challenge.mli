(** Ceremony challenges: random bytes the relying party issues, keeps server-side (for
    example in the session) and expects back, signed, exactly once.

    A challenge is only safe if it is single use: remove it from wherever it is kept
    before calling {!Registration.verify} or {!Authentication.verify}, whatever the
    outcome, so that a captured response cannot be replayed. *)

open! Core

(** A challenge: its bytes, when it was issued and when it expires. The sexp shows the
    bytes in base64url. *)
type t [@@deriving sexp_of, compare, equal]

(** Default length: 32 bytes. The specification asks for at least 16. *)
val default_length : int

(** Default lifetime: 5 minutes, in line with the default ceremony timeout. *)
val default_ttl : Time_ns.Span.t

(** [create ~now ()] draws fresh bytes from the operating system's CSPRNG (Cryptokit's
    [Random.secure_rng]: getrandom or /dev/urandom). [?random] replaces the source, for
    deterministic tests only. Raises if [length] is below 16. *)
val create
  :  ?random:(int -> string)
  -> ?length:int
  -> ?ttl:Time_ns.Span.t
  -> now:Time_ns.t
  -> unit
  -> t

(** [of_bytes ~issued_at ~expires_at bytes] rebuilds a challenge kept elsewhere. *)
val of_bytes : issued_at:Time_ns.t -> expires_at:Time_ns.t -> string -> t

val bytes : t -> string
(** The raw challenge bytes. *)

(** The value to put in the options JSON. *)
val to_base64url : t -> string

val issued_at : t -> Time_ns.t
(** When {!create} was called. *)
val expires_at : t -> Time_ns.t
(** The first instant at which {!check} reports [Challenge_expired]. *)

(** [check t ~now ~received] compares the challenge from clientDataJSON with [t] in
    constant time, then the expiry ([now] at or after [expires_at] is expired). *)
val check : t -> now:Time_ns.t -> received:string -> (unit, Verify_error.t) result

(** [equal_constant_time a b] does not leak where two strings differ; it does leak their
    lengths. *)
val equal_constant_time : string -> string -> bool

(** Stable serialisation, for keeping challenges in a session store. *)
module Stable : sig
  (** Version 1. *)
  module V1 : sig
    type nonrec t = t [@@deriving sexp, bin_io, compare, equal]
    (** Same type as {!Challenge.t}. *)
  end
end

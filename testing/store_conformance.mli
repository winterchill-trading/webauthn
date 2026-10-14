(** Scenarios every {!Webauthn.Store.S} implementation must pass: idempotent adds,
    conflicting IDs, per-user listing, the sign-count compare-and-set and removal.

    Run it from a service's own tests against its database-backed store, with a fresh,
    empty store per call of [create]. *)

open! Core
open Async_kernel

module Make (S : Webauthn.Store.S) : sig
  (** Runs every scenario; raises with a description of the first violation. Returns the
      names of the scenarios that passed. *)
  val run : create:(unit -> S.t Deferred.t) -> string list Deferred.t
end

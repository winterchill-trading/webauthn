(** Who the relying party is: its RP ID and the web origins allowed to run ceremonies for
    it. One value per deployment, shared by registration and authentication. *)

open! Core

(** An RP ID with its allowed origins and top origins. *)
type t [@@deriving sexp_of]

(** [create ~id ~origins ()]: [id] is the RP ID (a registrable domain such as
    ["example.org"]); [origins] are the exact serialised origins allowed in clientDataJSON
    (["https://example.org"], ["https://login.example.org"], or an app's origin such as
    ["android:apk-key-hash:..."]). Comparison is exact string equality; list every origin
    the RP serves.

    [top_origins] enables ceremonies inside cross-origin iframes: when it is empty (the
    default) any response with [crossOrigin: true] is refused. When it is not empty, a
    cross-origin response is accepted if its [topOrigin] is in the list, or if it has no
    [topOrigin] (Level 2 browsers do not send one).

    Errors when [id] or [origins] is empty. *)
val create
  :  ?top_origins:string list
  -> id:string
  -> origins:string list
  -> unit
  -> t Or_error.t

val id : t -> string
(** The RP ID. *)
val origins : t -> string list
(** Origins allowed in clientDataJSON. *)
val top_origins : t -> string list
(** Top origins allowed for cross-origin iframes; empty refuses them. *)

(** SHA-256 of the RP ID, as authenticator data carries it. *)
val id_hash : t -> string

(** [check_client_data t data ~ceremony] checks [type] (["webauthn.create"] or
    ["webauthn.get"]), [origin], [crossOrigin] and [topOrigin]. The challenge is checked
    separately by {!Challenge.check}. *)
val check_client_data
  :  t
  -> Client_data.t
  -> ceremony:[ `Create | `Get ]
  -> (unit, Verify_error.t) result

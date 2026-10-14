(** [CollectedClientData] (WebAuthn section 5.8.1): the JSON the browser builds and the
    authenticator signs over by hash. The relying party must check every field it relies
    on against the raw JSON it received, never against a re-serialisation. *)

open! Core

type t =
  { type_ : string (** ["webauthn.create"] or ["webauthn.get"]. *)
  ; challenge : string (** Decoded challenge bytes. *)
  ; origin : string
  ; cross_origin : bool (** [false] when absent. *)
  ; top_origin : string option
  }
[@@deriving sexp, compare, equal]

(** [parse json] reads clientDataJSON. It requires a JSON object with string [type],
    base64url [challenge] and string [origin]; [crossOrigin] must be a boolean and
    [topOrigin] a string when present. Other members are ignored, as the specification
    allows the client to add them. *)
val parse : string -> t Or_error.t

(** [to_json t] writes clientDataJSON in the order the specification's "limited
    verification algorithm" expects ([type], [challenge], [origin], [crossOrigin],
    [topOrigin]); used by test authenticators. *)
val to_json : t -> string

(** SHA-256 of the raw JSON bytes, the value authenticators sign. *)
val hash : string -> string

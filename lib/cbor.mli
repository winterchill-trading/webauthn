(** CBOR (RFC 8949) data items: a decoder strict enough for untrusted WebAuthn input and
    an encoder that writes the core deterministic encoding.

    WebAuthn carries the attestation object, COSE public keys and extension outputs as
    CBOR. The decoder accepts every well-formed item (definite and indefinite lengths,
    tags, half/single/double floats, simple values) with these limits, which a relying
    party wants for input from the network:

    - nesting deeper than {!max_depth} is rejected;
    - integers outside OCaml's 63-bit [int] are rejected with an explicit error (no
      WebAuthn structure uses larger values);
    - a declared length longer than the remaining input is rejected before anything is
      allocated;
    - text strings must be valid UTF-8;
    - maps with duplicate keys are rejected (CTAP2 forbids them, and accepting them would
      let two parsers disagree on a value);
    - the reserved additional-information values 28 to 30 and a [break] outside an
      indefinite-length item are rejected. *)

open! Core

type t =
  | Int of int (** Major types 0 and 1. *)
  | Bytes of string (** Major type 2, chunks of an indefinite string joined. *)
  | Text of string (** Major type 3, UTF-8. *)
  | Array of t list
  | Map of (t * t) list (** In input order; keys are unique. *)
  | Tag of int * t
  | Bool of bool
  | Null
  | Undefined
  | Simple of int (** Unassigned simple values (0 to 19 and 32 to 255). *)
  | Float of float
[@@deriving sexp, compare, equal]

(** Nesting limit of the decoder: 32. *)
val max_depth : int

(** [decode s] decodes exactly one item that spans all of [s]. Trailing bytes are an
    error. *)
val decode : string -> t Or_error.t

(** [decode_prefix s ~pos] decodes one item starting at byte [pos] and returns it with the
    position just after it. Authenticator data needs this: the credential public key is
    followed by more CBOR with no length prefix. *)
val decode_prefix : string -> pos:int -> (t * int) Or_error.t

(** [encode t] writes the core deterministic encoding (RFC 8949 section 4.2.1): shortest
    argument forms, definite lengths, map keys sorted by their encoded bytes, floats as
    the shortest of half, single or double that keeps the value. [Map] entries are
    reordered; [encode] does not check for duplicate keys. *)
val encode : t -> string

(** [diagnostic t] is RFC 8949 diagnostic notation, e.g. [{1: 2, 3: -7, -1: h'0102'}]. *)
val diagnostic : t -> string

(** {2 Reading decoded items}

    Each accessor returns an error naming what was expected and what was found. *)

(** [find map key] is the value stored under [key] in a [Map], or [None]. *)
val find : (t * t) list -> t -> t option

val to_int : t -> int Or_error.t
val to_bytes : t -> string Or_error.t
val to_text : t -> string Or_error.t
val to_map : t -> (t * t) list Or_error.t
val to_array : t -> t list Or_error.t

(** [kind t] names the item's type for error messages: ["int"], ["bytes"], ["map"]... *)
val kind : t -> string

(** Generator of items {!decode} accepts and {!encode} round-trips: unique map keys, valid
    UTF-8, finite floats, at most a few levels deep. *)
val quickcheck_generator : t Quickcheck.Generator.t

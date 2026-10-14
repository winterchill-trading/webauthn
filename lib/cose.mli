(** COSE public keys (RFC 9052, RFC 9053) as WebAuthn authenticators return them in the
    attested credential data, and the signature algorithms this library verifies. *)

open! Core

module Algorithm : sig
  (** COSE algorithm identifiers this library can verify. *)
  type t =
    | Es256 (** ECDSA on P-256 with SHA-256, identifier -7. *)
    | Rs256 (** RSASSA-PKCS1-v1_5 with SHA-256, identifier -257. *)
  [@@deriving sexp, compare, equal, enumerate, hash]

  (** The COSE identifier: -7 or -257. *)
  val to_int : t -> int

  (** [of_int id] is [None] for identifiers this library does not verify. *)
  val of_int : int -> t option

  (** Name of a COSE algorithm identifier from the IANA registry, for error messages, also
      for ones this library does not support (e.g. [-8] is ["EdDSA"]). *)
  val name_of_int : int -> string
end

type t =
  | Es256 of P256.public_key
  | Rs256 of Rsa.public_key
[@@deriving sexp_of, compare, equal]

val algorithm : t -> Algorithm.t

(** [of_cbor item] reads a COSE_Key map. It requires the key type (label 1), the algorithm
    (label 3, which WebAuthn makes mandatory) and the parameters for that type: curve 1
    (P-256) with 32-byte [x] and [y] for EC2 keys, modulus and exponent for RSA keys. A
    map that carries private key material (label -4 for EC2, -3 to -12 for RSA) is
    rejected. The error for an algorithm this library does not verify starts with
    ["unsupported COSE algorithm"]. *)
val of_cbor : Cbor.t -> t Or_error.t

(** [decode bytes] is [of_cbor] over a CBOR byte string. *)
val decode : string -> t Or_error.t

(** [to_cbor t] is the COSE_Key map, and [encode t] its deterministic CBOR encoding.
    [decode (encode t)] is [Ok t]. *)
val to_cbor : t -> Cbor.t

val encode : t -> string

(** [verify key ~message ~signature] checks a WebAuthn signature: DER ECDSA for ES256,
    PKCS #1 v1.5 for RS256, both over SHA-256 of [message]. *)
val verify : t -> message:string -> signature:string -> bool

(** Stable serialisation: the key travels as its COSE encoding, so the format does not
    depend on this library's internal representation. *)
module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving sexp, bin_io, compare, equal]
  end
end

(** ECDSA signature verification on NIST P-256 (secp256r1) with SHA-256: the COSE
    algorithm ES256 (-7), which nearly every passkey uses.

    Written over zarith because the usual OCaml elliptic-curve package cannot be built on
    the OxCaml switch. Verification handles only public data (key, message, signature), so
    it does not need to run in constant time. The arithmetic uses Jacobian coordinates and
    Shamir's trick for [u1 G + u2 Q]; one verification takes about 0.7 ms on an Apple
    M-series laptop. *)

open! Core

(** A point on the curve, never the point at infinity. *)
type public_key [@@deriving sexp_of, compare, equal]

(** [public_key_of_coordinates ~x ~y] takes the two 32-byte big-endian affine coordinates
    (COSE_Key labels -2 and -3) and checks that the point is on the curve. *)
val public_key_of_coordinates : x:string -> y:string -> public_key Or_error.t

(** [public_key_of_uncompressed s] takes the 65-byte SEC 1 form [04 || x || y]. *)
val public_key_of_uncompressed : string -> public_key Or_error.t

(** The 32-byte big-endian [x] and [y] coordinates. *)
val coordinates : public_key -> string * string

(** [verify key ~message ~signature] checks a DER-encoded
    [Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }] over SHA-256 of [message].

    The DER parser is strict (minimal lengths, minimal positive integers, no trailing
    bytes), so a signature has one accepted encoding and malleated encodings fail. [r] and
    [s] must lie in [1, n-1]; high [s] values are accepted, as WebAuthn does not require
    low-S signatures. *)
val verify : public_key -> message:string -> signature:string -> bool

(** Signing, for test authenticators only. This code is NOT constant time and leaks the
    secret through timing; never use it with a key that protects anything. *)
module Testing_only : sig
  (** [public_key secret] is [secret * G]. [secret] is a big-endian 32-byte scalar in
      [1, n-1]. *)
  val public_key : secret:string -> public_key

  (** [sign ~secret message] signs SHA-256 of [message] with an RFC 6979 deterministic
      nonce and returns the DER encoding. *)
  val sign : secret:string -> string -> string
end

(** RSASSA-PKCS1-v1_5 signature verification with SHA-256: the COSE algorithm RS256
    (-257), used by Windows Hello and some security keys. The padding check compares the
    whole decoded block against the one expected encoding, which avoids the classic
    lenient-parser forgeries. Moduli of any bit length are handled, including ones that
    are not a multiple of 8 bits. *)

open! Core

type public_key [@@deriving sexp_of, compare, equal]

(** Smallest accepted modulus: 2048 bits. *)
val min_modulus_bits : int

(** [public_key ~n ~e] takes the big-endian modulus and public exponent (COSE_Key labels
    -1 and -2). Leading zero bytes are ignored. The modulus must be odd and at least
    {!min_modulus_bits} bits; the exponent must be odd and greater than 1. *)
val public_key : n:string -> e:string -> public_key Or_error.t

(** Modulus size in bits. *)
val modulus_bits : public_key -> int

(** The big-endian modulus and exponent without leading zero bytes. *)
val components : public_key -> [ `N of string ] * [ `E of string ]

(** [verify key ~message ~signature] checks a PKCS #1 v1.5 signature over SHA-256 of
    [message]. The signature must be exactly as long as the modulus and smaller than it.
    The DigestInfo must carry the explicit NULL parameters. *)
val verify : public_key -> message:string -> signature:string -> bool

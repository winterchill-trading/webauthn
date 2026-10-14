(** Authenticator data (WebAuthn section 6.1): the bytes an authenticator signs, carrying
    the RP ID hash, flags, signature counter and, at registration, the new credential. *)

open! Core

module Flags : sig
  type t =
    { user_present : bool (** UP, bit 0. *)
    ; user_verified : bool (** UV, bit 2. *)
    ; backup_eligible : bool (** BE, bit 3: the credential may be synced (a passkey). *)
    ; backed_up : bool (** BS, bit 4: the credential is currently backed up. *)
    ; attested_credential_data : bool (** AT, bit 6. *)
    ; extension_data : bool (** ED, bit 7. *)
    }
  [@@deriving sexp, compare, equal]

  (** Reserved bits 1 and 5 are ignored, as the specification requires. *)
  val of_byte : int -> t

  val to_byte : t -> int
end

module Aaguid : sig
  (** The 16-byte authenticator model identifier. All zeros means unknown, which is what a
      "none" attestation usually carries. *)
  type t [@@deriving sexp, compare, equal, hash, bin_io]

  val of_bytes : string -> t Or_error.t
  val to_bytes : t -> string
  val zero : t

  (** Lowercase UUID text, e.g. ["adce0002-35bc-c60a-648b-0b25f1f05503"]. *)
  val to_string : t -> string

  val of_string : string -> t Or_error.t

  module Stable : sig
    module V1 : sig
      type nonrec t = t [@@deriving sexp, bin_io, compare, equal]
    end
  end
end

type attested_credential =
  { aaguid : Aaguid.t
  ; credential_id : string
  ; public_key : Cose.t
  }
[@@deriving sexp_of]

type t =
  { rp_id_hash : string (** SHA-256 of the RP ID, 32 bytes. *)
  ; flags : Flags.t
  ; sign_count : int (** Unsigned 32-bit counter, 0 when the authenticator has none. *)
  ; attested_credential : attested_credential option (** Present iff [flags.AT]. *)
  ; extensions : Cbor.t option (** Present iff [flags.ED]; a CBOR map. *)
  }
[@@deriving sexp_of]

(** Longest credential ID accepted: 1023 bytes (WebAuthn Level 3). *)
val max_credential_id_length : int

(** [parse bytes] decodes authenticator data. It checks that the AT and ED flags match
    what follows the 37-byte header, that the extensions are a CBOR map, that nothing
    trails, and that a credential ID is between 1 and {!max_credential_id_length} bytes. A
    public key with an algorithm this library does not verify is an error. *)
val parse : string -> t Or_error.t

(** [encode t] writes the bytes [parse] reads; used by test authenticators. *)
val encode : t -> string

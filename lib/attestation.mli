(** Attestation objects (WebAuthn section 6.5) and the statement formats this library
    verifies.

    Verified formats: ["none"] (empty statement) and ["packed"] self attestation (no
    certificate chain, signed by the credential key itself). Every other format, and
    ["packed"] with an [x5c] chain, would need X.509 path validation against the
    authenticator vendors' roots (FIDO Metadata Service); this library does not do that. A
    {!Policy.t} decides whether such responses are refused or accepted with the statement
    left unverified. Relying parties that ask for attestation ["none"] (the default in
    {!Options.Creation}) normally receive ["none"] anyway. *)

open! Core

module Policy : sig
  type t =
    | None_or_self
    (** Accept ["none"] and ["packed"] self attestation only; refuse the rest with
        [Unsupported_attestation]. The default. *)
    | Accept_unverified
    (** Also accept other formats without checking their statement. The credential is
        still bound to the ceremony by the authenticator data checks; what is lost is
        proof of the authenticator model. *)
  [@@deriving sexp, compare, equal]
end

module Kind : sig
  type t =
    | None_
    | Self
    | Unverified of string (** Format name. *)
  [@@deriving sexp, compare, equal]
end

type t =
  { fmt : string
  ; auth_data : string (** Raw authenticator data bytes. *)
  ; statement : (Cbor.t * Cbor.t) list (** [attStmt]. *)
  }
[@@deriving sexp_of]

(** [decode bytes] reads the CBOR map [{fmt: text, attStmt: map, authData: bytes}]. *)
val decode : string -> t Or_error.t

(** [encode t] writes the attestation object; used by test authenticators. *)
val encode : t -> string

(** [verify policy t ~parsed ~client_data_hash] checks the statement against the parsed
    authenticator data [parsed] (which must carry the attested credential). For ["packed"]
    self attestation the statement's [alg] must match the credential key's algorithm and
    [sig] must verify over [authData || client_data_hash] with that key. *)
val verify
  :  Policy.t
  -> t
  -> parsed:Authenticator_data.t
  -> client_data_hash:string
  -> (Kind.t, Verify_error.t) result

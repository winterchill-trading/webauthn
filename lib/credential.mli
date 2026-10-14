(** The credential record a relying party keeps per registered passkey (WebAuthn section
    4, "credential record"), produced by {!Registration.verify} and updated after each
    {!Authentication.verify}. *)

open! Core

module Transport : sig
  (** [AuthenticatorTransport] hints, reported by the browser at registration and passed
      back in [allowCredentials] / [excludeCredentials]. Unknown values are kept so that
      newer browsers' hints survive a round trip. *)
  type t =
    | Usb
    | Nfc
    | Ble
    | Smart_card
    | Hybrid
    | Internal
    | Other of string
  [@@deriving sexp, compare, equal, hash, bin_io]

  (** The WebAuthn string: ["usb"], ["nfc"], ["ble"], ["smart-card"], ["hybrid"],
      ["internal"], or the [Other] text. *)
  val to_string : t -> string

  (** Inverse of {!to_string}; unknown strings become [Other]. *)
  val of_string : string -> t
end

type t =
  { id : string (** Credential ID bytes (shown as base64url in sexps). *)
  ; public_key : Cose.t
  ; sign_count : int (** Last signature counter seen; 0 if the authenticator has none. *)
  ; user_handle : string (** The [user.id] bytes given at registration. *)
  ; aaguid : Authenticator_data.Aaguid.t
  ; transports : Transport.t list
  ; backup_eligible : bool (** BE at registration; it can never change. *)
  ; backed_up : bool (** BS, updated at every authentication. *)
  ; user_verified : bool (** UV at registration ([uvInitialized]). *)
  ; attestation_format : string (** ["none"], ["packed"], ... *)
  }
[@@deriving sexp, compare, equal]

(** Stable serialisation for stores. Byte strings are base64url in the sexp form. *)
module Stable : sig
  (** Version 1. *)
  module V1 : sig
    (** Same type as {!Credential.t}. *)
    type nonrec t = t [@@deriving sexp, bin_io, compare, equal]
  end
end

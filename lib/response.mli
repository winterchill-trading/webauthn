(** The JSON a browser sends back: [PublicKeyCredential.toJSON()] (WebAuthn Level 3
    section 5.1.8), i.e. [RegistrationResponseJSON] and [AuthenticationResponseJSON] with
    every byte string in unpadded base64url. Libraries that serialise the credential by
    hand produce the same shape. *)

open! Core

module Registration : sig
  type t =
    { id : string (** As sent: base64url of [raw_id]. *)
    ; raw_id : string (** Decoded bytes. *)
    ; client_data_json : string (** Raw JSON bytes. *)
    ; attestation_object : string (** CBOR bytes. *)
    ; transports : Credential.Transport.t list
    ; authenticator_attachment : string option (** ["platform"] or ["cross-platform"]. *)
    ; client_extension_results : Yojson.Safe.t
    }
  [@@deriving sexp_of]

  (** [of_json json] reads [RegistrationResponseJSON]. [type] must be ["public-key"] and
      [id] must equal the base64url form of [rawId]. *)
  val of_json : Yojson.Safe.t -> t Or_error.t

  val of_string : string -> t Or_error.t
  val to_json : t -> Yojson.Safe.t
end

module Authentication : sig
  type t =
    { id : string
    ; raw_id : string
    ; client_data_json : string
    ; authenticator_data : string
    ; signature : string
    ; user_handle : string option (** Absent or [null] when the authenticator has none. *)
    ; authenticator_attachment : string option
    ; client_extension_results : Yojson.Safe.t
    }
  [@@deriving sexp_of]

  val of_json : Yojson.Safe.t -> t Or_error.t
  val of_string : string -> t Or_error.t
  val to_json : t -> Yojson.Safe.t
end

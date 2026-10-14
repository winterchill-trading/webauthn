(** Options for [navigator.credentials.create] and [navigator.credentials.get] in their
    JSON form ([PublicKeyCredentialCreationOptionsJSON] and
    [PublicKeyCredentialRequestOptionsJSON], WebAuthn Level 3), which a page passes to
    [PublicKeyCredential.parseCreationOptionsFromJSON] / [parseRequestOptionsFromJSON] (or
    decodes by hand on older browsers). *)

open! Core

module User_verification : sig
  (** Whether the authenticator must verify the user (PIN, biometrics). The relying party
      enforces [Required] itself at verification time: the browser's answer is only a
      request. *)
  type t =
    | Required
    | Preferred
    | Discouraged
  [@@deriving sexp, compare, equal, enumerate]

  (** ["required"], ["preferred"], ["discouraged"]. *)
  val to_string : t -> string
  (** The WebAuthn enumeration string. *)
end

module Resident_key : sig
  (** Whether to create a discoverable credential (a passkey that can sign in without a
      user name first). *)
  type t =
    | Required
    | Preferred
    | Discouraged
  [@@deriving sexp, compare, equal, enumerate]

  val to_string : t -> string
  (** The WebAuthn enumeration string. *)
end

module Attestation_conveyance : sig
  type t =
    | None_ (** The default; the browser may strip attestation. *)
    | Indirect
    | Direct
    | Enterprise
  [@@deriving sexp, compare, equal, enumerate]

  val to_string : t -> string
  (** The WebAuthn enumeration string. *)
end

module Authenticator_attachment : sig
  type t =
    | Platform (** Built into the device (Touch ID, Windows Hello, Android). *)
    | Cross_platform (** Roaming: security keys, a phone over hybrid transport. *)
  [@@deriving sexp, compare, equal, enumerate]

  val to_string : t -> string
  (** The WebAuthn enumeration string. *)
end

module Hint : sig
  (** Level 3 [hints], ordered by preference. *)
  type t =
    | Security_key
    | Client_device
    | Hybrid
  [@@deriving sexp, compare, equal, enumerate]

  val to_string : t -> string
  (** The WebAuthn enumeration string. *)
end

module Descriptor : sig
  (** [PublicKeyCredentialDescriptor] for [excludeCredentials] / [allowCredentials]. *)
  type t =
    { id : string
    ; transports : Credential.Transport.t list
    }
  [@@deriving sexp, compare, equal]

  val of_credential : Credential.t -> t
  (** The ID and transports of a stored credential. *)
  val to_json : t -> Yojson.Safe.t
  (** [{"type": "public-key", "id": ..., "transports": [...]}]. *)
end

module Creation : sig
  type t =
    { rp_id : string
    ; rp_name : string
    ; user_id : string (** Opaque bytes, 1 to 64, no personal data. *)
    ; user_name : string
    ; user_display_name : string
    ; challenge : Challenge.t
    ; algorithms : Cose.Algorithm.t list (** In preference order. *)
    ; timeout : Time_ns.Span.t
    ; exclude_credentials : Descriptor.t list
    ; authenticator_attachment : Authenticator_attachment.t option
    ; resident_key : Resident_key.t
    ; user_verification : User_verification.t
    ; attestation : Attestation_conveyance.t
    ; hints : Hint.t list
    ; cred_props : bool (** Ask for the [credProps] extension output. *)
    }
  [@@deriving sexp_of]

  (** Defaults: algorithms [[Es256; Rs256]], timeout 5 minutes, no exclusions, any
      attachment, resident key [Preferred], user verification [Preferred], attestation
      [None_], no hints, [credProps] requested. Errors when [user_id] is empty or longer
      than 64 bytes, or [algorithms] is empty. *)
  val create
    :  ?algorithms:Cose.Algorithm.t list
    -> ?timeout:Time_ns.Span.t
    -> ?exclude_credentials:Descriptor.t list
    -> ?authenticator_attachment:Authenticator_attachment.t
    -> ?resident_key:Resident_key.t
    -> ?user_verification:User_verification.t
    -> ?attestation:Attestation_conveyance.t
    -> ?hints:Hint.t list
    -> ?cred_props:bool
    -> rp_id:string
    -> rp_name:string
    -> user_id:string
    -> user_name:string
    -> user_display_name:string
    -> challenge:Challenge.t
    -> unit
    -> t Or_error.t

  (** [PublicKeyCredentialCreationOptionsJSON]. [requireResidentKey] is set from
      [resident_key] for Level 1 browsers. *)
  val to_json : t -> Yojson.Safe.t
  (** [{"type": "public-key", "id": ..., "transports": [...]}]. *)
end

module Request : sig
  type t =
    { rp_id : string
    ; challenge : Challenge.t
    ; timeout : Time_ns.Span.t
    ; allow_credentials : Descriptor.t list
    (** Empty for a discoverable-credential (user-name-less) sign-in. *)
    ; user_verification : User_verification.t
    ; hints : Hint.t list
    }
  [@@deriving sexp_of]

  (** Defaults: timeout 5 minutes, no allow list, user verification [Preferred]. *)
  val create
    :  ?timeout:Time_ns.Span.t
    -> ?allow_credentials:Descriptor.t list
    -> ?user_verification:User_verification.t
    -> ?hints:Hint.t list
    -> rp_id:string
    -> challenge:Challenge.t
    -> unit
    -> t

  (** [PublicKeyCredentialRequestOptionsJSON]. *)
  val to_json : t -> Yojson.Safe.t
  (** [{"type": "public-key", "id": ..., "transports": [...]}]. *)
end

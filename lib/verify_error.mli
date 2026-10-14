(** Why a registration or authentication response was refused.

    Each case has a stable snake_case {!code} suitable for an API error body. Messages
    meant for the end user should not distinguish between most of these: tell the user the
    attempt failed and log the code. *)

open! Core

type t =
  | Malformed of string (** The response could not be decoded; the detail says where. *)
  | Wrong_ceremony of
      { expected : string
      ; got : string
      } (** clientDataJSON [type] is not ["webauthn.create"] / ["webauthn.get"]. *)
  | Challenge_mismatch
  | Challenge_expired
  | Origin_not_allowed of string
  | Cross_origin_not_allowed
  | Top_origin_not_allowed of string
  | Rp_id_mismatch
  (** The RP ID hash in the authenticator data is not SHA-256 of the RP ID. *)
  | User_not_present
  | User_not_verified
  | Invalid_backup_flags (** BS set without BE. *)
  | Backup_eligibility_changed (** BE differs from the value recorded at registration. *)
  | Missing_credential_data (** Registration without attested credential data. *)
  | Credential_id_mismatch (** [rawId] differs from the credential ID it should equal. *)
  | Unsupported_algorithm of int
  | Algorithm_not_allowed of int (** Supported, but not in the RP's accepted list. *)
  | Unsupported_attestation of string (** Attestation format refused by the policy. *)
  | Invalid_attestation of string
  | Credential_not_allowed (** Not in [allowCredentials]. *)
  | User_handle_mismatch
  | Missing_user_handle (** Discoverable-credential login without [userHandle]. *)
  | Bad_signature
  | Sign_count_regressed of
      { stored : int
      ; received : int
      } (** Possible cloned authenticator. *)
[@@deriving sexp, compare, equal]

(** Stable identifier, e.g. ["challenge_mismatch"], ["sign_count_regressed"]. *)
val code : t -> string

(** All codes, for documentation and API schemas. *)
val all_codes : string list

val to_error : t -> Error.t

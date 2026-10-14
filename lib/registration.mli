(** Registration ceremony verification (WebAuthn section 7.1, "Registering a New
    Credential"). *)

open! Core

type t =
  { credential : Credential.t (** Store this, keyed by [credential.id]. *)
  ; attestation : Attestation.Kind.t
  ; authenticator_attachment : string option (** As reported by the browser. *)
  ; client_extension_results : Yojson.Safe.t
  (** E.g. [{"credProps": {"rk": true}}]; informational, not signed. *)
  }
[@@deriving sexp_of]

(** [verify rp response ~challenge ~now ~user_handle] runs every relying-party step of
    section 7.1 except the "credential ID not already registered" lookup, which needs the
    caller's store (see {!Store.S.add}).

    In order: clientDataJSON [type], challenge (constant time) and expiry, origin and
    cross-origin rules ({!Relying_party.check_client_data}), the attestation object, RP ID
    hash, user presence, user verification when [user_verification] is [Required] (default
    [Preferred], which does not require it), backup flags consistency, the attested
    credential (present, ID equal to [rawId], at most 1023 bytes), the key algorithm
    against [algorithms] (default ES256 and RS256), then the attestation statement under
    [attestation] (default {!Attestation.Policy.None_or_self}).

    [user_handle] is the [user.id] the options carried; it is copied into the credential
    record. Consume the challenge before calling, whatever the outcome. *)
val verify
  :  ?user_verification:Options.User_verification.t
  -> ?algorithms:Cose.Algorithm.t list
  -> ?attestation:Attestation.Policy.t
  -> Relying_party.t
  -> Response.Registration.t
  -> challenge:Challenge.t
  -> now:Time_ns.t
  -> user_handle:string
  -> (t, Verify_error.t) result

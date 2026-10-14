(** Authentication ceremony verification (WebAuthn section 7.2, "Verifying an
    Authentication Assertion"). *)

open! Core

module Sign_count : sig
  (** What the signature counter says about the authenticator. *)
  type t =
    | Not_used (** Stored and received counters are both 0: many passkeys never count. *)
    | Advanced (** Strictly greater than the stored value. *)
    | Regressed of
        { stored : int
        ; received : int
        }
    (** Not greater although one side is non-zero: the authenticator may have been cloned.
        Returned only with [~on_sign_count_regression:`Accept]. *)
  [@@deriving sexp, compare, equal]
end

type t =
  { credential : Credential.t
  (** The record with [sign_count], [backed_up] and [user_verified] updated; write it back
      (see {!Store.S.update}). *)
  ; user_verified : bool
  ; sign_count : Sign_count.t
  ; authenticator_attachment : string option
  ; client_extension_results : Yojson.Safe.t
  }
[@@deriving sexp_of]

(** [credential_id response] is the [rawId] to look the stored credential up by. *)
val credential_id : Response.Authentication.t -> string

(** [verify rp response ~challenge ~now ~credential] runs the relying-party steps of
    section 7.2 against the stored [credential]:

    - if [allow_credentials] is not empty, [rawId] must be one of them; if it is empty
      (discoverable-credential sign-in) the response must carry a [userHandle];
    - [rawId] must equal [credential.id], and a [userHandle], when present, must equal
      [credential.user_handle];
    - clientDataJSON [type], challenge and expiry, origin and cross-origin rules;
    - RP ID hash, user presence, user verification when [user_verification] is [Required],
      BS only with BE, BE unchanged since registration;
    - the signature over [authenticatorData || SHA-256(clientDataJSON)] with the stored
      public key;
    - the signature counter: a regression is refused with [Sign_count_regressed] unless
      [on_sign_count_regression] is [`Accept] (default [`Reject]). *)
val verify
  :  ?user_verification:Options.User_verification.t
  -> ?allow_credentials:string list
  -> ?on_sign_count_regression:[ `Reject | `Accept ]
  -> Relying_party.t
  -> Response.Authentication.t
  -> challenge:Challenge.t
  -> now:Time_ns.t
  -> credential:Credential.t
  -> (t, Verify_error.t) result

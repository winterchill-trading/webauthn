(** A software authenticator for tests: it holds one credential and produces the JSON
    responses a browser would send, with knobs to produce every kind of invalid response a
    relying party must refuse.

    Not for production: its ES256 signing is not constant time
    ({!Webauthn.P256.Testing_only}) and its keys are derived from a seed. *)

open! Core
open Webauthn

(** One credential with its private key and signature counter. *)
type t

(** [create ~seed ()] derives the key and the credential ID from [seed], so the same seed
    always gives the same credential. ES256 by default; RS256 generates a 2048-bit key
    (slow, about a second). [counting] (default [true]) makes the signature counter
    advance by one per assertion; when false it stays 0, as most passkeys do. *)
val create
  :  ?algorithm:Cose.Algorithm.t
  -> ?aaguid:Authenticator_data.Aaguid.t
  -> ?backup_eligible:bool
  -> ?counting:bool
  -> ?credential_id:string
  -> seed:string
  -> unit
  -> t

val credential_id : t -> string
(** The credential ID it registers and asserts with. *)
val public_key : t -> Cose.t
(** The credential public key. *)

(** Current value of the signature counter (the last one signed). *)
val sign_count : t -> int

(** [register t ~rp_id ~origin ~challenge ()] builds a [RegistrationResponseJSON] answer
    to a creation request. Defaults: attestation ["none"], user present and verified,
    backed up iff backup eligible, transports [["internal"]], no cross-origin.

    The optional arguments break one thing each: [type_] (clientDataJSON type),
    [rp_id_hash_of] (the RP ID whose hash goes in the authenticator data), [attestation]
    ([`Packed_self] signs a packed statement; [`Packed_self_bad_signature] signs the wrong
    bytes; [`Format name] writes an unverifiable format with an empty statement), [raw_id]
    (the [rawId] sent, default the credential ID). *)
val register
  :  ?type_:string
  -> ?cross_origin:bool
  -> ?top_origin:string
  -> ?rp_id_hash_of:string
  -> ?user_present:bool
  -> ?user_verified:bool
  -> ?backed_up:bool
  -> ?attestation:
       [ `None | `Packed_self | `Packed_self_bad_signature | `Format of string ]
  -> ?transports:Credential.Transport.t list
  -> ?raw_id:string
  -> t
  -> rp_id:string
  -> origin:string
  -> challenge:string
  -> unit
  -> Response.Registration.t

(** [authenticate t ~rp_id ~origin ~challenge ()] builds an [AuthenticationResponseJSON]
    and advances the counter (when counting). [sign_count] overrides the counter value
    signed (without changing the internal one); [tamper_signature] flips a bit of the
    signature; [backup_eligible] overrides the BE flag. *)
val authenticate
  :  ?type_:string
  -> ?cross_origin:bool
  -> ?top_origin:string
  -> ?rp_id_hash_of:string
  -> ?user_present:bool
  -> ?user_verified:bool
  -> ?backup_eligible:bool
  -> ?backed_up:bool
  -> ?sign_count:int
  -> ?user_handle:string
  -> ?raw_id:string
  -> ?tamper_signature:bool
  -> t
  -> rp_id:string
  -> origin:string
  -> challenge:string
  -> unit
  -> Response.Authentication.t

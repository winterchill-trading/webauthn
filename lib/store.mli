(** Where credential records live. The library never persists anything itself; a service
    implements {!S} over its own database and runs the conformance suite in
    [webauthn.testing] ([Webauthn_testing.Store_conformance]) against it. {!Store_memory}
    is the reference implementation, for tests and single-process tools. *)

open! Core
open Async_kernel

module type S = sig
  type t

  (** [add t credential] registers a credential (WebAuthn 7.1 step 26: a credential ID
      must not be registered twice). Idempotent: adding a record equal to the stored one
      returns [`Already_present]; a different record under the same ID returns
      [Error `Id_taken], which the relying party should treat as a failed registration. *)
  val add
    :  t
    -> Credential.t
    -> ([ `Added | `Already_present ], [ `Id_taken ]) result Deferred.t

  val find : t -> id:string -> Credential.t option Deferred.t

  (** All credentials of a user, ordered by credential ID; feeds [excludeCredentials] and
      account pages. *)
  val list_for_user : t -> user_handle:string -> Credential.t list Deferred.t

  (** [update t credential] stores the result of {!Authentication.verify}. Only the fields
      an assertion can change are written: [sign_count], [backed_up] and [user_verified].
      It is a compare-and-set on the counter: the write happens when the new [sign_count]
      is greater than the stored one, or both are 0; otherwise [`Stale] (another assertion
      with the same or a later counter got there first, which for a counting authenticator
      means a replay or a clone). *)
  val update : t -> Credential.t -> [ `Updated | `Stale | `Not_found ] Deferred.t

  val remove : t -> id:string -> [ `Removed | `Not_found ] Deferred.t
end

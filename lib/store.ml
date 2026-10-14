open! Core
open Async_kernel

module type S = sig
  type t

  val add
    :  t
    -> Credential.t
    -> ([ `Added | `Already_present ], [ `Id_taken ]) result Deferred.t

  val find : t -> id:string -> Credential.t option Deferred.t
  val list_for_user : t -> user_handle:string -> Credential.t list Deferred.t
  val update : t -> Credential.t -> [ `Updated | `Stale | `Not_found ] Deferred.t
  val remove : t -> id:string -> [ `Removed | `Not_found ] Deferred.t
end

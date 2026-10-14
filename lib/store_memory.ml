open! Core
open Async_kernel

type t = (string, Credential.t) Hashtbl.t

let create () = Hashtbl.create (module String)
let length = Hashtbl.length

let add t (c : Credential.t) =
  return
    (match Hashtbl.find t c.id with
     | None ->
       Hashtbl.set t ~key:c.id ~data:c;
       Ok `Added
     | Some existing ->
       if Credential.equal existing c then Ok `Already_present else Error `Id_taken)
;;

let find t ~id = return (Hashtbl.find t id)

let list_for_user t ~user_handle =
  Hashtbl.data t
  |> List.filter ~f:(fun (c : Credential.t) -> String.equal c.user_handle user_handle)
  |> List.sort ~compare:(fun (a : Credential.t) b -> String.compare a.id b.id)
  |> return
;;

let update t (c : Credential.t) =
  return
    (match Hashtbl.find t c.id with
     | None -> `Not_found
     | Some (stored : Credential.t) ->
       if c.sign_count > stored.sign_count || (c.sign_count = 0 && stored.sign_count = 0)
       then (
         Hashtbl.set
           t
           ~key:c.id
           ~data:
             { stored with
               sign_count = c.sign_count
             ; backed_up = c.backed_up
             ; user_verified = c.user_verified
             };
         `Updated)
       else `Stale)
;;

let remove t ~id =
  return
    (if Hashtbl.mem t id
     then (
       Hashtbl.remove t id;
       `Removed)
     else `Not_found)
;;

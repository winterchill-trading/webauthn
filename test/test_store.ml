open! Core
open! Async
open Webauthn
module Conformance = Webauthn_testing.Store_conformance.Make (Store_memory)

let%expect_test "Store_memory passes the conformance suite" =
  let%map passed = Conformance.run ~create:(fun () -> return (Store_memory.create ())) in
  List.iter passed ~f:print_endline;
  [%expect
    {|
    add is idempotent and refuses a different record under the same id
    find of an unknown id is None
    list_for_user returns that user's credentials ordered by id
    update writes a higher counter and refuses an equal or lower one
    update only writes the fields an assertion can change
    counterless credentials (always 0) update every time
    remove
    |}]
;;

(* A store that forgets to compare counters must fail the suite. *)
module Broken = struct
  include Store_memory

  let update t (c : Credential.t) =
    match%bind find t ~id:c.id with
    | None -> return `Not_found
    | Some _ ->
      let%bind _ = remove t ~id:c.id in
      let%map _ = add t c in
      `Updated
  ;;
end

let%expect_test "a store without the compare-and-set fails" =
  let module C = Webauthn_testing.Store_conformance.Make (Broken) in
  let%map result =
    Monitor.try_with ~extract_exn:true (fun () ->
      C.run ~create:(fun () -> return (Store_memory.create ())))
  in
  print_s [%sexp (Result.map result ~f:ignore : (unit, Exn.t) Result.t)];
  [%expect
    {|
    (Error
     ("store conformance failure" (name equal) (expected Stale) (got Updated)))
    |}]
;;

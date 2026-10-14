open! Core
open Async_kernel
open Webauthn

let credential ?(sign_count = 0) ?(user_handle = "user-a") id : Credential.t =
  { id
  ; public_key =
      Es256 (P256.Testing_only.public_key ~secret:(String.make 31 '\x00' ^ "\x07"))
  ; sign_count
  ; user_handle
  ; aaguid = Authenticator_data.Aaguid.zero
  ; transports = [ Internal; Hybrid ]
  ; backup_eligible = true
  ; backed_up = false
  ; user_verified = true
  ; attestation_format = "none"
  }
;;

module Make (S : Store.S) = struct
  let expect name ~sexp_of got expected =
    if not (Poly.equal got expected)
    then
      raise_s
        [%message
          "store conformance failure"
            (name : string)
            ~expected:(sexp_of expected : Sexp.t)
            ~got:(sexp_of got : Sexp.t)]
  ;;

  let sexp_of_add = function
    | Ok `Added -> Sexp.Atom "Added"
    | Ok `Already_present -> Atom "Already_present"
    | Error `Id_taken -> Atom "Id_taken"
  ;;

  let sexp_of_update = function
    | `Updated -> Sexp.Atom "Updated"
    | `Stale -> Atom "Stale"
    | `Not_found -> Atom "Not_found"
  ;;

  let sexp_of_remove = function
    | `Removed -> Sexp.Atom "Removed"
    | `Not_found -> Atom "Not_found"
  ;;

  let ids l = List.map l ~f:(fun (c : Credential.t) -> Base64url.encode c.id)

  let scenarios =
    [ ( "add is idempotent and refuses a different record under the same id"
      , fun s ->
          let c = credential "id-1" in
          let%bind r1 = S.add s c in
          expect "first add" ~sexp_of:sexp_of_add r1 (Ok `Added);
          let%bind r2 = S.add s c in
          expect "same record again" ~sexp_of:sexp_of_add r2 (Ok `Already_present);
          let%bind r3 = S.add s { c with user_handle = "user-b" } in
          expect "other record, same id" ~sexp_of:sexp_of_add r3 (Error `Id_taken);
          let%map found = S.find s ~id:"id-1" in
          expect "find" ~sexp_of:[%sexp_of: Credential.t option] found (Some c) )
    ; ( "find of an unknown id is None"
      , fun s ->
          let%map found = S.find s ~id:"missing" in
          expect "find" ~sexp_of:[%sexp_of: Credential.t option] found None )
    ; ( "list_for_user returns that user's credentials ordered by id"
      , fun s ->
          let%bind (_ : _ list) =
            Deferred.List.map
              ~how:`Sequential
              [ credential "id-c"
              ; credential "id-a"
              ; credential ~user_handle:"user-b" "id-b"
              ]
              ~f:(S.add s)
          in
          let%bind a = S.list_for_user s ~user_handle:"user-a" in
          expect
            "user-a"
            ~sexp_of:[%sexp_of: string list]
            (ids a)
            (ids [ credential "id-a"; credential "id-c" ]);
          let%map none = S.list_for_user s ~user_handle:"nobody" in
          expect "nobody" ~sexp_of:[%sexp_of: string list] (ids none) [] )
    ; ( "update writes a higher counter and refuses an equal or lower one"
      , fun s ->
          let c = credential ~sign_count:5 "id-1" in
          let%bind _ = S.add s c in
          let%bind u1 = S.update s { c with sign_count = 6; backed_up = true } in
          expect "higher" ~sexp_of:sexp_of_update u1 `Updated;
          let%bind u2 = S.update s { c with sign_count = 6 } in
          expect "equal" ~sexp_of:sexp_of_update u2 `Stale;
          let%bind u3 = S.update s { c with sign_count = 3 } in
          expect "lower" ~sexp_of:sexp_of_update u3 `Stale;
          let%bind u4 = S.update s (credential ~sign_count:9 "missing") in
          expect "unknown" ~sexp_of:sexp_of_update u4 `Not_found;
          let%map found = S.find s ~id:"id-1" in
          expect
            "stored after updates"
            ~sexp_of:[%sexp_of: Credential.t option]
            found
            (Some { c with sign_count = 6; backed_up = true }) )
    ; ( "update only writes the fields an assertion can change"
      , fun s ->
          let c = credential ~sign_count:1 "id-1" in
          let%bind _ = S.add s c in
          let%bind u =
            S.update
              s
              { c with
                sign_count = 2
              ; user_handle = "someone-else"
              ; transports = []
              ; attestation_format = "packed"
              }
          in
          expect "update" ~sexp_of:sexp_of_update u `Updated;
          let%map found = S.find s ~id:"id-1" in
          expect
            "immutable fields kept"
            ~sexp_of:[%sexp_of: Credential.t option]
            found
            (Some { c with sign_count = 2 }) )
    ; ( "counterless credentials (always 0) update every time"
      , fun s ->
          let c = credential "id-1" in
          let%bind _ = S.add s c in
          let%bind u1 = S.update s { c with backed_up = true } in
          expect "first" ~sexp_of:sexp_of_update u1 `Updated;
          let%map u2 = S.update s { c with backed_up = false } in
          expect "second" ~sexp_of:sexp_of_update u2 `Updated )
    ; ( "remove"
      , fun s ->
          let%bind _ = S.add s (credential "id-1") in
          let%bind r1 = S.remove s ~id:"id-1" in
          expect "present" ~sexp_of:sexp_of_remove r1 `Removed;
          let%bind r2 = S.remove s ~id:"id-1" in
          expect "gone" ~sexp_of:sexp_of_remove r2 `Not_found;
          let%map found = S.find s ~id:"id-1" in
          expect "find after remove" ~sexp_of:[%sexp_of: Credential.t option] found None
      )
    ]
  ;;

  let run ~create =
    Deferred.List.map ~how:`Sequential scenarios ~f:(fun (name, scenario) ->
      let%bind s = create () in
      let%map () = scenario s in
      name)
  ;;
end

(* Registration and authentication against the software authenticator: the happy path, one
   refusal per check, and properties over random inputs. *)
open! Core
open Webauthn
module Soft = Webauthn_testing.Soft_authenticator

let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"
let rp_id = "example.org"
let origin = "https://example.org"

let rp =
  Relying_party.create ~id:rp_id ~origins:[ origin; "https://login.example.org" ] ()
  |> Or_error.ok_exn
;;

let challenge_of seed =
  Challenge.create
    ~random:(fun n ->
      String.prefix
        (String.concat (List.init 4 ~f:(fun _ -> seed ^ "-padding-padding")))
        n)
    ~now
    ()
;;

let show = function
  | Ok _ -> print_endline "ok"
  | Error e -> print_s [%sexp (e : Verify_error.t)]
;;

let register
  ?user_verification
  ?algorithms
  ?attestation
  ?(at = now)
  soft
  challenge
  response
  =
  ignore (soft : Soft.t);
  Registration.verify
    ?user_verification
    ?algorithms
    ?attestation
    rp
    response
    ~challenge
    ~now:at
    ~user_handle:"user-1"
;;

let%expect_test "registration refusals, one per check" =
  let soft = Soft.create ~seed:"reg" () in
  let challenge = challenge_of "reg" in
  let c = Challenge.bytes challenge in
  let reg
    ?type_
    ?cross_origin
    ?top_origin
    ?rp_id_hash_of
    ?user_present
    ?user_verified
    ?backed_up
    ?attestation
    ?raw_id
    ?(origin = origin)
    ?(challenge_sent = c)
    ()
    =
    Soft.register
      ?type_
      ?cross_origin
      ?top_origin
      ?rp_id_hash_of
      ?user_present
      ?user_verified
      ?backed_up
      ?attestation
      ?raw_id
      soft
      ~rp_id
      ~origin
      ~challenge:challenge_sent
      ()
  in
  let run ?user_verification ?algorithms ?policy ?at r =
    show
      (register ?user_verification ?algorithms ?attestation:policy ?at soft challenge r)
  in
  run (reg ());
  run (reg ~origin:"https://login.example.org" ());
  run (reg ~attestation:`Packed_self ());
  run (reg ~type_:"webauthn.get" ());
  run (reg ~challenge_sent:"other" ());
  run ~at:(Time_ns.add now (Time_ns.Span.of_int_sec 301)) (reg ());
  run (reg ~origin:"https://evil.example" ());
  run (reg ~cross_origin:true ());
  run (reg ~top_origin:"https://example.com" ());
  run (reg ~rp_id_hash_of:"evil.example" ());
  run (reg ~user_present:false ());
  run ~user_verification:Required (reg ~user_verified:false ());
  run (reg ~user_verified:false ());
  run (reg ~raw_id:"another id" ());
  run ~algorithms:[ Rs256 ] (reg ());
  run (reg ~attestation:`Packed_self_bad_signature ());
  run (reg ~attestation:(`Format "tpm") ());
  run ~policy:Accept_unverified (reg ~attestation:(`Format "tpm") ());
  let not_eligible = Soft.create ~seed:"reg" ~backup_eligible:false () in
  show
    (register
       not_eligible
       challenge
       (Soft.register not_eligible ~backed_up:true ~rp_id ~origin ~challenge:c ()));
  [%expect
    {|
    ok
    ok
    ok
    (Wrong_ceremony (expected webauthn.create) (got webauthn.get))
    Challenge_mismatch
    Challenge_expired
    (Origin_not_allowed https://evil.example)
    Cross_origin_not_allowed
    (Top_origin_not_allowed https://example.com)
    Rp_id_mismatch
    User_not_present
    User_not_verified
    ok
    Credential_id_mismatch
    (Algorithm_not_allowed -7)
    (Invalid_attestation "packed: self attestation signature")
    (Unsupported_attestation tpm)
    ok
    Invalid_backup_flags
    |}]
;;

let registered ?(seed = "auth") ?algorithm ?counting () =
  let soft = Soft.create ?algorithm ?counting ~seed () in
  let challenge = challenge_of "registration" in
  let r =
    register
      soft
      challenge
      (Soft.register soft ~rp_id ~origin ~challenge:(Challenge.bytes challenge) ())
    |> Result.map_error ~f:Verify_error.to_error
    |> Or_error.ok_exn
  in
  soft, r.credential
;;

let%expect_test "authentication refusals, one per check" =
  let soft, credential = registered () in
  let challenge = challenge_of "auth" in
  let c = Challenge.bytes challenge in
  let auth
    ?type_
    ?cross_origin
    ?top_origin
    ?rp_id_hash_of
    ?user_present
    ?user_verified
    ?backup_eligible
    ?backed_up
    ?sign_count
    ?(user_handle = Some "user-1")
    ?raw_id
    ?tamper_signature
    ?(challenge_sent = c)
    ()
    =
    Soft.authenticate
      ?type_
      ?cross_origin
      ?top_origin
      ?rp_id_hash_of
      ?user_present
      ?user_verified
      ?backup_eligible
      ?backed_up
      ?sign_count
      ?user_handle
      ?raw_id
      ?tamper_signature
      soft
      ~rp_id
      ~origin
      ~challenge:challenge_sent
      ()
  in
  let run
    ?user_verification
    ?allow_credentials
    ?on_sign_count_regression
    ?(credential = credential)
    r
    =
    match
      Authentication.verify
        ?user_verification
        ?allow_credentials
        ?on_sign_count_regression
        rp
        r
        ~challenge
        ~now
        ~credential
    with
    | Ok a ->
      let status = a.sign_count in
      let stored = a.credential.sign_count in
      print_s [%sexp "ok", (status : Authentication.Sign_count.t), (stored : int)]
    | Error e -> print_s [%sexp (e : Verify_error.t)]
  in
  run (auth ());
  run ~allow_credentials:[ credential.id ] (auth ~user_handle:None ());
  run ~allow_credentials:[ "other" ] (auth ());
  run (auth ~user_handle:None ());
  run (auth ~user_handle:(Some "user-2") ());
  run (auth ~raw_id:"other" ());
  run (auth ~type_:"webauthn.create" ());
  run (auth ~challenge_sent:"other" ());
  run (auth ~rp_id_hash_of:"evil.example" ());
  run (auth ~user_present:false ());
  run ~user_verification:Required (auth ~user_verified:false ());
  run (auth ~backup_eligible:false ());
  run (auth ~tamper_signature:true ());
  run ~credential:{ credential with sign_count = 100 } (auth ());
  run
    ~credential:{ credential with sign_count = 100 }
    ~on_sign_count_regression:`Accept
    (auth ());
  run (auth ~sign_count:0 ());
  [%expect
    {|
    (ok Advanced 1)
    (ok Advanced 2)
    Credential_not_allowed
    Missing_user_handle
    User_handle_mismatch
    Credential_id_mismatch
    (Wrong_ceremony (expected webauthn.get) (got webauthn.create))
    Challenge_mismatch
    Rp_id_mismatch
    User_not_present
    User_not_verified
    Backup_eligibility_changed
    Bad_signature
    (Sign_count_regressed (stored 100) (received 14))
    (ok (Regressed (stored 100) (received 15)) 100)
    (ok Not_used 0)
    |}]
;;

let%expect_test "RS256 credentials" =
  let soft, credential = registered ~seed:"rsa" ~algorithm:Rs256 () in
  let challenge = challenge_of "auth" in
  let r =
    Soft.authenticate
      soft
      ~rp_id
      ~origin
      ~challenge:(Challenge.bytes challenge)
      ~user_handle:"user-1"
      ()
  in
  show (Authentication.verify rp r ~challenge ~now ~credential);
  print_s [%sexp (Cose.algorithm credential.public_key : Cose.Algorithm.t)];
  [%expect {|
    ok
    Rs256
    |}]
;;

(* Random challenges and either algorithm's flags: the round trip always succeeds, and
   flipping any single bit of the signed data or the signature is always refused. *)
let%test_unit "assertions: valid ones pass, any flipped bit fails" =
  let soft, credential = registered ~seed:"property" ~counting:false () in
  Quickcheck.test
    ~trials:30
    (Quickcheck.Generator.tuple3
       (String.gen_with_length 32 Char.quickcheck_generator)
       Bool.quickcheck_generator
       (Int.gen_incl 0 1_000_000))
    ~sexp_of:[%sexp_of: string * bool * int]
    ~f:(fun (bytes, user_verified, bit) ->
      let challenge =
        Challenge.of_bytes
          ~issued_at:now
          ~expires_at:(Time_ns.add now Challenge.default_ttl)
          bytes
      in
      let r =
        Soft.authenticate
          soft
          ~user_verified
          ~user_handle:"user-1"
          ~rp_id
          ~origin
          ~challenge:bytes
          ()
      in
      let verify r = Authentication.verify rp r ~challenge ~now ~credential in
      assert (Result.is_ok (verify r));
      let flip s =
        let b = Bytes.of_string s in
        let i = bit / 8 % Bytes.length b in
        Bytes.set
          b
          i
          (Char.of_int_exn (Char.to_int (Bytes.get b i) lxor (1 lsl (bit % 8))));
        Bytes.to_string b
      in
      assert (
        Result.is_error (verify { r with authenticator_data = flip r.authenticator_data }));
      assert (
        Result.is_error (verify { r with client_data_json = flip r.client_data_json }));
      assert (Result.is_error (verify { r with signature = flip r.signature })))
;;

let%test_unit "registration responses survive the JSON round trip" =
  let soft = Soft.create ~seed:"json" () in
  Quickcheck.test
    ~trials:20
    (String.gen_with_length 32 Char.quickcheck_generator)
    ~sexp_of:String.sexp_of_t
    ~f:(fun bytes ->
      let challenge =
        Challenge.of_bytes
          ~issued_at:now
          ~expires_at:(Time_ns.add now Challenge.default_ttl)
          bytes
      in
      let r = Soft.register soft ~rp_id ~origin ~challenge:bytes () in
      let json = Yojson.Safe.to_string (Response.Registration.to_json r) in
      let r' = Response.Registration.of_string json |> Or_error.ok_exn in
      assert (Result.is_ok (register soft challenge r')))
;;

open! Core
open Webauthn

let now = Time_ns.of_string_with_utc_offset "2026-10-14 12:00:00Z"

let%expect_test "check" =
  let random n = String.init n ~f:(fun i -> Char.of_int_exn i) in
  let c = Challenge.create ~random ~now () in
  print_s [%sexp (c : Challenge.t)];
  let at ?(received = Challenge.bytes c) offset =
    print_s
      [%sexp
        (Challenge.check
           c
           ~now:(Time_ns.add now (Time_ns.Span.of_int_sec offset))
           ~received
         : (unit, Verify_error.t) result)]
  in
  at 0;
  at 299;
  at 300;
  at 0 ~received:"other";
  at 0 ~received:(String.make 32 '\x00');
  [%expect
    {|
    ((bytes AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8)
     (issued_at "2026-10-14 12:00:00Z") (expires_at "2026-10-14 12:05:00Z"))
    (Ok ())
    (Ok ())
    (Error Challenge_expired)
    (Error Challenge_mismatch)
    (Error Challenge_mismatch)
    |}]
;;

let%expect_test "system randomness gives distinct challenges of the requested length" =
  let a = Challenge.create ~now () in
  let b = Challenge.create ~now ~length:16 () in
  print_s
    [%sexp
      (String.length (Challenge.bytes a) : int)
      , (String.length (Challenge.bytes b) : int)
      , (String.equal (Challenge.bytes a) (Challenge.bytes (Challenge.create ~now ()))
         : bool)];
  print_s
    [%sexp
      (Or_error.try_with (fun () -> Challenge.create ~now ~length:15 ())
       |> Result.is_error
       : bool)];
  [%expect {|
    (32 16 false)
    true
    |}]
;;

let%expect_test "stable form" =
  let c = Challenge.create ~random:(fun n -> String.make n 'a') ~now () in
  let bin = Binable.to_string (module Challenge.Stable.V1) c in
  print_s
    [%sexp
      (Challenge.equal c (Binable.of_string (module Challenge.Stable.V1) bin) : bool)
      , (Challenge.equal
           c
           (Challenge.Stable.V1.t_of_sexp (Challenge.Stable.V1.sexp_of_t c))
         : bool)];
  print_endline [%bin_digest: Challenge.Stable.V1.t];
  [%expect {|
    (true true)
    ab2c011c77d9562fb5ddd1d3bb3dd44d
    |}]
;;

let%test_unit "constant-time equality agrees with String.equal" =
  Quickcheck.test
    (Quickcheck.Generator.both String.quickcheck_generator String.quickcheck_generator)
    ~sexp_of:[%sexp_of: string * string]
    ~f:(fun (a, b) ->
      [%test_result: bool] (Challenge.equal_constant_time a b) ~expect:(String.equal a b);
      assert (Challenge.equal_constant_time a a))
;;

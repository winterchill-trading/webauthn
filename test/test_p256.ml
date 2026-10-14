open! Core
open Webauthn
module U = Yojson.Safe.Util

let%expect_test "Wycheproof ecdsa_secp256r1_sha256" =
  let doc = Vectors.json "wycheproof/ecdsa_secp256r1_sha256_test.json" in
  let counts = Hashtbl.create (module String) in
  let mismatches = ref [] in
  List.iter
    (U.member "testGroups" doc |> U.to_list)
    ~f:(fun group ->
      let key =
        U.member "publicKey" group
        |> U.member "uncompressed"
        |> U.to_string
        |> Vectors.of_hex
        |> P256.public_key_of_uncompressed
      in
      List.iter
        (U.member "tests" group |> U.to_list)
        ~f:(fun t ->
          let id = U.member "tcId" t |> U.to_int in
          let expected = U.member "result" t |> U.to_string in
          let got =
            match key with
            | Error _ -> false
            | Ok key ->
              P256.verify
                key
                ~message:(U.member "msg" t |> U.to_string |> Vectors.of_hex)
                ~signature:(U.member "sig" t |> U.to_string |> Vectors.of_hex)
          in
          let outcome =
            sprintf "%s -> %s" expected (if got then "accept" else "reject")
          in
          Hashtbl.incr counts outcome;
          match expected, got with
          | "valid", false | "invalid", true -> mismatches := id :: !mismatches
          | _ -> ()));
  let mismatches = List.rev !mismatches in
  print_s
    [%sexp
      (Hashtbl.to_alist counts |> List.sort ~compare:[%compare: string * int]
       : (string * int) list)
      , (mismatches : int list)];
  [%expect {| ((("invalid -> reject" 310) ("valid -> accept" 174)) ()) |}]
;;

(* RFC 6979 appendix A.2.5, P-256 with SHA-256, message "sample". *)
let%expect_test "RFC 6979 deterministic signature" =
  let secret =
    Vectors.of_hex "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  in
  let key = P256.Testing_only.public_key ~secret in
  let x, y = P256.coordinates key in
  print_endline (Vectors.to_hex x);
  print_endline (Vectors.to_hex y);
  let signature = P256.Testing_only.sign ~secret "sample" in
  print_endline (Vectors.to_hex signature);
  print_s [%sexp (P256.verify key ~message:"sample" ~signature : bool)];
  [%expect
    {|
    60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
    7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
    3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8
    true
    |}]
;;

let%expect_test "key parsing" =
  let show r = print_s [%sexp (Result.map r ~f:(fun _ -> ()) : unit Or_error.t)] in
  show
    (P256.public_key_of_coordinates ~x:(String.make 32 '\x01') ~y:(String.make 32 '\x01'));
  show (P256.public_key_of_coordinates ~x:"short" ~y:(String.make 32 '\x01'));
  show (P256.public_key_of_uncompressed ("\x02" ^ String.make 64 '\x00'));
  [%expect
    {|
    (Error "P-256 point is not on the curve")
    (Error ("P-256 coordinates must be 32 bytes each" (x 5) (y 32)))
    (Error "expected a 65-byte uncompressed P-256 point")
    |}]
;;

let secret_gen =
  Quickcheck.Generator.map
    (String.gen_with_length 32 Char.quickcheck_generator)
    ~f:(fun s -> "\x01" ^ String.drop_prefix s 1)
;;

let%test_unit "sign then verify, and any changed message byte fails" =
  Quickcheck.test
    ~trials:20
    (Quickcheck.Generator.both secret_gen String.quickcheck_generator)
    ~sexp_of:[%sexp_of: string * string]
    ~f:(fun (secret, message) ->
      let key = P256.Testing_only.public_key ~secret in
      let signature = P256.Testing_only.sign ~secret message in
      assert (P256.verify key ~message ~signature);
      assert (not (P256.verify key ~message:(message ^ "x") ~signature));
      let other = P256.Testing_only.public_key ~secret:(String.rev secret) in
      assert (not (P256.verify other ~message ~signature)))
;;

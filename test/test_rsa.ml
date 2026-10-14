open! Core
open Webauthn
module U = Yojson.Safe.Util

let run file =
  let doc = Vectors.json file in
  let counts = Hashtbl.create (module String) in
  let mismatches = ref [] in
  List.iter
    (U.member "testGroups" doc |> U.to_list)
    ~f:(fun group ->
      let pk = U.member "publicKey" group in
      let key =
        Rsa.public_key
          ~n:(U.member "modulus" pk |> U.to_string |> Vectors.of_hex)
          ~e:(U.member "publicExponent" pk |> U.to_string |> Vectors.of_hex)
        |> Or_error.ok_exn
      in
      List.iter
        (U.member "tests" group |> U.to_list)
        ~f:(fun t ->
          let id = U.member "tcId" t |> U.to_int in
          let expected = U.member "result" t |> U.to_string in
          let got =
            Rsa.verify
              key
              ~message:(U.member "msg" t |> U.to_string |> Vectors.of_hex)
              ~signature:(U.member "sig" t |> U.to_string |> Vectors.of_hex)
          in
          Hashtbl.incr
            counts
            (sprintf "%s -> %s" expected (if got then "accept" else "reject"));
          match expected, got with
          | "valid", false | "invalid", true -> mismatches := id :: !mismatches
          | _ -> ()));
  let mismatches = List.rev !mismatches in
  print_s
    [%sexp
      (Hashtbl.to_alist counts |> List.sort ~compare:[%compare: string * int]
       : (string * int) list)
      , (mismatches : int list)]
;;

(* The one "acceptable" case per file omits the NULL parameters in the DigestInfo (flag
   MissingNull); this library requires them, as RFC 8017 does. *)
let%expect_test "Wycheproof RSASSA-PKCS1-v1_5 SHA-256" =
  run "wycheproof/rsa_signature_2048_sha256_test.json";
  run "wycheproof/rsa_signature_3072_sha256_test.json";
  [%expect
    {|
    ((("acceptable -> reject" 1) ("invalid -> reject" 249) ("valid -> accept" 9))
     ())
    ((("acceptable -> reject" 1) ("invalid -> reject" 250) ("valid -> accept" 8))
     ())
    |}]
;;

let%expect_test "key checks" =
  let show ~n ~e =
    print_s
      [%sexp (Result.map (Rsa.public_key ~n ~e) ~f:Rsa.modulus_bits : int Or_error.t)]
  in
  let odd bytes = String.make (bytes - 1) '\xff' ^ "\x01" in
  show ~n:(odd 128) ~e:"\x01\x00\x01";
  show ~n:("\x00\x00" ^ odd 256) ~e:"\x01\x00\x01";
  show ~n:(String.make 256 '\xff' ^ "\x00") ~e:"\x03";
  show ~n:(odd 256) ~e:"\x01";
  show ~n:(odd 256) ~e:"\x01\x00\x00";
  [%expect
    {|
    (Error ("RSA modulus too small" (bits 1024) (min_modulus_bits 2048)))
    (Ok 2048)
    (Error "RSA modulus is even")
    (Error "RSA public exponent must be odd and greater than 1")
    (Error "RSA public exponent must be odd and greater than 1")
    |}]
;;

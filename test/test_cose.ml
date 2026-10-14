open! Core
open Webauthn

let es256_key =
  P256.Testing_only.public_key
    ~secret:
      (Vectors.of_hex "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
;;

let x, y = P256.coordinates es256_key

let ec2 extra =
  Cbor.Map
    ([ Cbor.Int 1, Cbor.Int 2
     ; Int 3, Int (-7)
     ; Int (-1), Int 1
     ; Int (-2), Bytes x
     ; Int (-3), Bytes y
     ]
     @ extra)
;;

let show item =
  print_endline
    (match Cose.of_cbor item with
     | Ok k -> "ok " ^ Sexp.to_string (Cose.Algorithm.sexp_of_t (Cose.algorithm k))
     | Error e -> Error.to_string_hum e)
;;

let%expect_test "COSE_Key parsing" =
  show (ec2 []);
  show (ec2 [ Int (-4), Bytes "secret" ]);
  show
    (Map
       [ Int 1, Int 2
       ; Int 3, Int (-7)
       ; Int (-1), Int 2
       ; Int (-2), Bytes x
       ; Int (-3), Bytes y
       ]);
  show (Map [ Int 1, Int 2; Int (-1), Int 1; Int (-2), Bytes x; Int (-3), Bytes y ]);
  show (Map [ Int 1, Int 1; Int 3, Int (-8); Int (-1), Int 6; Int (-2), Bytes x ]);
  show (Map [ Int 1, Int 2; Int 3, Int (-35); Int (-1), Int 2 ]);
  show (Map [ Int 1, Int 3; Int 3, Int (-7) ]);
  show (Bytes "not a map");
  [%expect
    {|
    ok Es256
    COSE_Key: private key parameter d present
    ("COSE_Key: ES256 requires curve P-256 (1)" (crv 2))
    ("COSE_Key: missing parameter" (label 3) alg)
    ("unsupported COSE algorithm" (alg EdDSA) (alg -8))
    ("unsupported COSE algorithm" (alg ES384) (alg -35))
    ("COSE_Key: key type does not match algorithm" (kty 3) (alg Es256))
    (COSE_Key ("CBOR: unexpected item" (expected map) (got bytes)))
    |}]
;;

let%expect_test "encode, decode and the stable forms" =
  let key = Cose.Es256 es256_key in
  let bytes = Cose.encode key in
  print_endline (Vectors.to_hex bytes);
  print_s [%sexp (Result.map (Cose.decode bytes) ~f:(Cose.equal key) : bool Or_error.t)];
  let sexp = Cose.Stable.V1.sexp_of_t key in
  print_s sexp;
  print_s [%sexp (Cose.equal key (Cose.Stable.V1.t_of_sexp sexp) : bool)];
  let bin = Binable.to_string (module Cose.Stable.V1) key in
  print_s [%sexp (Cose.equal key (Binable.of_string (module Cose.Stable.V1) bin) : bool)];
  print_endline [%bin_digest: Cose.Stable.V1.t];
  [%expect
    {|
    a501020326200121582060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb62258207903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
    (Ok true)
    pQECAyYgASFYIGD-1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p-2IlggeQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk
    true
    true
    d9a8da25d5656b016fb4dbdc2e4197fb
    |}]
;;

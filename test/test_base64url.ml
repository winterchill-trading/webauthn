open! Core
open Webauthn

let%expect_test "RFC 4648 vectors in the URL alphabet" =
  List.iter
    [ ""; "f"; "fo"; "foo"; "foob"; "fooba"; "foobar"; "\xfb\xff\xbf" ]
    ~f:(fun s ->
      let e = Base64url.encode s in
      printf "%S -> %s -> %S\n" s e (Base64url.decode_exn e));
  [%expect
    {|
    "" ->  -> ""
    "f" -> Zg -> "f"
    "fo" -> Zm8 -> "fo"
    "foo" -> Zm9v -> "foo"
    "foob" -> Zm9vYg -> "foob"
    "fooba" -> Zm9vYmE -> "fooba"
    "foobar" -> Zm9vYmFy -> "foobar"
    "\251\255\191" -> -_-_ -> "\251\255\191"
    |}]
;;

let%expect_test "rejections" =
  List.iter [ "Zg=="; "Zh"; "Z"; "+/+/"; "Zm9v\n"; "Zm 9v" ] ~f:(fun s ->
    print_s [%sexp (s : string), (Base64url.decode s : string Or_error.t)]);
  [%expect
    {|
    (Zg== (Ok f))
    (Zh (Error "base64url: non-zero trailing bits"))
    (Z (Error ("base64url: impossible length" (n 1))))
    (+/+/ (Error ("base64url: invalid character" (char +) (position 0))))
    ("Zm9v\n" (Error ("base64url: invalid character" (char "\n") (position 4))))
    ("Zm 9v" (Error ("base64url: invalid character" (char " ") (position 2))))
    |}]
;;

let%test_unit "round trip" =
  Quickcheck.test String.quickcheck_generator ~sexp_of:String.sexp_of_t ~f:(fun s ->
    [%test_result: string] (Base64url.decode_exn (Base64url.encode s)) ~expect:s)
;;

let%test_unit "encode is canonical: decode then encode returns the input" =
  Quickcheck.test String.quickcheck_generator ~sexp_of:String.sexp_of_t ~f:(fun s ->
    let e = Base64url.encode s in
    [%test_result: string] (Base64url.encode (Base64url.decode_exn e)) ~expect:e)
;;

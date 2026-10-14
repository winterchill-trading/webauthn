open! Core
open Webauthn

let of_hex h =
  String.init
    (String.length h / 2)
    ~f:(fun i ->
      Char.of_int_exn (Int.of_string ("0x" ^ String.sub h ~pos:(2 * i) ~len:2)))
;;

let to_hex s = String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c))

(* RFC 8949 appendix A: hex encoding, then the diagnostic notation we print. Items whose
   canonical encoding differs from the vector (indefinite lengths) are marked with the
   re-encoded form. *)
let%expect_test "RFC 8949 appendix A" =
  List.iter
    [ "00"
    ; "01"
    ; "0a"
    ; "17"
    ; "1818"
    ; "1819"
    ; "1864"
    ; "1903e8"
    ; "1a000f4240"
    ; "1b000000e8d4a51000"
    ; "20"
    ; "29"
    ; "3863"
    ; "3903e7"
    ; "f90000"
    ; "f98000"
    ; "f93c00"
    ; "fb3ff199999999999a"
    ; "f93e00"
    ; "f97bff"
    ; "fa47c35000"
    ; "fa7f7fffff"
    ; "fb7e37e43c8800759c"
    ; "f90001"
    ; "f90400"
    ; "f9c400"
    ; "fbc010666666666666"
    ; "f97c00"
    ; "f97e00"
    ; "f9fc00"
    ; "f4"
    ; "f5"
    ; "f6"
    ; "f7"
    ; "f0"
    ; "f818"
    ; "f8ff"
    ; "c074323031332d30332d32315432303a30343a30305a"
    ; "c11a514b67b0"
    ; "d74401020304"
    ; "40"
    ; "4401020304"
    ; "60"
    ; "6161"
    ; "6449455446"
    ; "62225c"
    ; "62c3bc"
    ; "63e6b0b4"
    ; "64f0908591"
    ; "80"
    ; "83010203"
    ; "8301820203820405"
    ; "a0"
    ; "a201020304"
    ; "a26161016162820203"
    ; "826161a161626163"
    ; "5f42010243030405ff"
    ; "7f657374726561646d696e67ff"
    ; "9fff"
    ; "9f018202039f0405ffff"
    ; "bf61610161629f0203ffff"
    ; "bf6346756ef563416d7421ff"
    ]
    ~f:(fun h ->
      match Cbor.decode (of_hex h) with
      | Error e -> printf "%s ERROR %s\n" h (Error.to_string_hum e)
      | Ok v ->
        let again = to_hex (Cbor.encode v) in
        printf
          "%s %s%s\n"
          h
          (Cbor.diagnostic v)
          (if String.equal again h then "" else " => " ^ again));
  [%expect
    {|
    00 0
    01 1
    0a 10
    17 23
    1818 24
    1819 25
    1864 100
    1903e8 1000
    1a000f4240 1000000
    1b000000e8d4a51000 1000000000000
    20 -1
    29 -10
    3863 -100
    3903e7 -1000
    f90000 0.0
    f98000 -0.0
    f93c00 1.0
    fb3ff199999999999a 1.1
    f93e00 1.5
    f97bff 65504.0
    fa47c35000 100000.0
    fa7f7fffff 3.4028234663852886e+38
    fb7e37e43c8800759c 1e+300
    f90001 5.9604644775390625e-08
    f90400 6.103515625e-05
    f9c400 -4.0
    fbc010666666666666 -4.1
    f97c00 Infinity
    f97e00 NaN
    f9fc00 -Infinity
    f4 false
    f5 true
    f6 null
    f7 undefined
    f0 simple(16)
    f818 ERROR ("CBOR: two-byte simple value below 32" (n 24) (at 0))
    f8ff simple(255)
    c074323031332d30332d32315432303a30343a30305a 0("2013-03-21T20:04:00Z")
    c11a514b67b0 1(1363896240)
    d74401020304 23(h'01020304')
    40 h''
    4401020304 h'01020304'
    60 ""
    6161 "a"
    6449455446 "IETF"
    62225c "\"\\"
    62c3bc "\195\188"
    63e6b0b4 "\230\176\180"
    64f0908591 "\240\144\133\145"
    80 []
    83010203 [1, 2, 3]
    8301820203820405 [1, [2, 3], [4, 5]]
    a0 {}
    a201020304 {1: 2, 3: 4}
    a26161016162820203 {"a": 1, "b": [2, 3]}
    826161a161626163 ["a", {"b": "c"}]
    5f42010243030405ff h'0102030405' => 450102030405
    7f657374726561646d696e67ff "streaming" => 6973747265616d696e67
    9fff [] => 80
    9f018202039f0405ffff [1, [2, 3], [4, 5]] => 8301820203820405
    bf61610161629f0203ffff {"a": 1, "b": [2, 3]} => a26161016162820203
    bf6346756ef563416d7421ff {"Fun": true, "Amt": -2} => a263416d74216346756ef5
    |}]
;;

let%expect_test "malformed and hostile input" =
  List.iter
    [ "", "empty"
    ; "18", "missing argument byte"
    ; "1b8000000000000000", "integer beyond 63 bits"
    ; "5a7fffffff", "byte string longer than the input"
    ; "9b00ffffffffffffff", "array length beyond the input"
    ; "1c", "reserved additional information"
    ; "ff", "break outside an indefinite item"
    ; "0001", "trailing bytes"
    ; "1f", "indefinite integer"
    ; "5f4101610262ff", "text chunk inside a byte string"
    ; "62c328", "invalid UTF-8"
    ; "a201020103", "duplicate map key"
    ; "9f01", "unterminated indefinite array"
    ; String.concat (List.init 40 ~f:(fun _ -> "81")) ^ "00", "nesting 41 deep"
    ]
    ~f:(fun (h, what) ->
      printf
        "%s: %s\n"
        what
        (match Cbor.decode (of_hex h) with
         | Ok v -> "accepted " ^ Cbor.diagnostic v
         | Error e -> Error.to_string_hum e));
  [%expect
    {|
    empty: ("CBOR: truncated input" (at 0) (needed 1) (available 0))
    missing argument byte: ("CBOR: truncated input" (at 1) (needed 1) (available 0))
    integer beyond 63 bits: ("CBOR: integer out of range" (at 1))
    byte string longer than the input: ("CBOR: truncated input" (at 5) (needed 2147483647) (available 0))
    array length beyond the input: ("CBOR: truncated input" (at 9) (needed 72057594037927935) (available 0))
    reserved additional information: ("CBOR: reserved additional information" (ai 28) (at 0))
    break outside an indefinite item: ("CBOR: unexpected break" (at 0))
    trailing bytes: ("CBOR: trailing bytes" (at 1) (total 2))
    indefinite integer: ("CBOR: indefinite length not allowed" "for an integer" (at 0))
    text chunk inside a byte string: ("CBOR: indefinite string chunk of another type" (at 3))
    invalid UTF-8: ("CBOR: text string is not valid UTF-8" (at 0))
    duplicate map key: ("CBOR: duplicate map key" (at 3))
    unterminated indefinite array: ("CBOR: truncated input" (at 2) (needed 1) (available 0))
    nesting 41 deep: ("CBOR: nesting too deep" (at 33))
    |}]
;;

let%expect_test "decode_prefix reports where the item ends" =
  let s = of_hex "a10102" ^ "rest" in
  print_s [%sexp (Cbor.decode_prefix s ~pos:0 : (Cbor.t * int) Or_error.t)];
  [%expect {| (Ok ((Map (((Int 1) (Int 2)))) 3)) |}]
;;

let rec normalize : Cbor.t -> Cbor.t = function
  | Array items -> Array (List.map items ~f:normalize)
  | Map entries ->
    Map
      (List.map entries ~f:(fun (k, v) -> normalize k, normalize v)
       |> List.sort ~compare:(fun (a, _) (b, _) ->
         String.compare (Cbor.encode a) (Cbor.encode b)))
  | Tag (n, v) -> Tag (n, normalize v)
  | v -> v
;;

let%test_unit "decode inverts encode, up to map entry order" =
  Quickcheck.test Cbor.quickcheck_generator ~sexp_of:Cbor.sexp_of_t ~f:(fun v ->
    let decoded = Cbor.decode (Cbor.encode v) |> Or_error.ok_exn in
    [%test_result: Cbor.t] decoded ~expect:(normalize v))
;;

let%test_unit "encode is deterministic: re-encoding a decoded item gives the same bytes" =
  Quickcheck.test Cbor.quickcheck_generator ~sexp_of:Cbor.sexp_of_t ~f:(fun v ->
    let e = Cbor.encode v in
    [%test_result: string] (Cbor.encode (Cbor.decode e |> Or_error.ok_exn)) ~expect:e)
;;

let%test_unit "arbitrary bytes never raise" =
  Quickcheck.test
    String.quickcheck_generator
    ~sexp_of:String.sexp_of_t
    ~trials:20_000
    ~f:(fun s -> ignore (Cbor.decode s : Cbor.t Or_error.t))
;;

let%test_unit "truncating an encoding is always an error" =
  Quickcheck.test Cbor.quickcheck_generator ~sexp_of:Cbor.sexp_of_t ~f:(fun v ->
    let e = Cbor.encode v in
    for len = 0 to String.length e - 1 do
      assert (Result.is_error (Cbor.decode (String.prefix e len)))
    done)
;;

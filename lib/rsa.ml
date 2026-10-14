open! Core

type public_key =
  { n : string
  ; e : string
  ; bits : int
  }
[@@deriving compare, equal]

let to_hex s = String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c))

let sexp_of_public_key t =
  [%sexp { bits : int = t.bits; n : string = to_hex t.n; e : string = to_hex t.e }]
;;

let min_modulus_bits = 2048
let strip s = String.lstrip s ~drop:(Char.equal '\x00')
let z_of_bytes s = if String.is_empty s then Z.zero else Z.of_string_base 16 (to_hex s)

let public_key ~n ~e =
  let n = strip n in
  let e = strip e in
  let nz = z_of_bytes n in
  let ez = z_of_bytes e in
  let bits = Z.numbits nz in
  if bits < min_modulus_bits
  then
    Or_error.error_s
      [%message "RSA modulus too small" (bits : int) (min_modulus_bits : int)]
  else if not (Z.testbit nz 0)
  then Or_error.error_string "RSA modulus is even"
  else if Z.leq ez Z.one || not (Z.testbit ez 0)
  then Or_error.error_string "RSA public exponent must be odd and greater than 1"
  else if Z.geq ez nz
  then Or_error.error_string "RSA public exponent not below the modulus"
  else Ok { n; e; bits }
;;

let modulus_bits t = t.bits
let components t = `N t.n, `E t.e

(* DER of DigestInfo { AlgorithmIdentifier { id-sha256, NULL }, OCTET STRING (32) },
   RFC 8017 section 9.2 note 1. *)
let sha256_digest_info_prefix =
  "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
;;

let verify t ~message ~signature =
  let k = String.length t.n in
  if String.length signature <> k || Z.geq (z_of_bytes signature) (z_of_bytes t.n)
  then false
  else (
    (* Plain modular exponentiation over zarith. Cryptokit 1.16's [RSA.unwrap_signature]
       sizes its output as [size / 8] bytes and raises for a modulus whose bit length is
       not a multiple of 8 (the 3482-bit key of the W3C RS256 example needs 436 bytes, it
       allocates 435). *)
    match Z.powm (z_of_bytes signature) (z_of_bytes t.e) (z_of_bytes t.n) with
    | exception _ -> false
    | em ->
      let em =
        let hex = Z.format "%x" em in
        let hex = if String.length hex % 2 = 1 then "0" ^ hex else hex in
        let raw =
          String.init
            (String.length hex / 2)
            ~f:(fun i ->
              Char.of_int_exn (Int.of_string ("0x" ^ String.sub hex ~pos:(2 * i) ~len:2)))
        in
        if String.length raw > k
        then raw
        else String.make (k - String.length raw) '\x00' ^ raw
      in
      let t_ =
        sha256_digest_info_prefix
        ^ Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) message
      in
      let ps_len = k - String.length t_ - 3 in
      ps_len >= 8 && String.equal em ("\x00\x01" ^ String.make ps_len '\xff' ^ "\x00" ^ t_))
;;

open! Core

let hex = Z.of_string_base 16
let p = hex "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
let b = hex "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
let n = hex "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
let gx = hex "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
let gy = hex "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
let modp x = Z.erem x p
let ( +: ) x y = modp (Z.add x y)
let ( -: ) x y = modp (Z.sub x y)
let ( *: ) x y = modp (Z.mul x y)
let small k = Z.of_int k

(* Jacobian coordinates: (X, Y, Z) stands for (X / Z^2, Y / Z^3); Z = 0 is the point at
   infinity. Formulas from the Explicit-Formulas Database (dbl-2001-b for a = -3,
   add-2007-bl). *)
type jacobian =
  { x : Z.t
  ; y : Z.t
  ; z : Z.t
  }

let infinity = { x = Z.one; y = Z.one; z = Z.zero }
let is_infinity q = Z.equal q.z Z.zero
let of_affine (x, y) = { x; y; z = Z.one }

let double q =
  if is_infinity q || Z.equal q.y Z.zero
  then infinity
  else (
    let delta = q.z *: q.z in
    let gamma = q.y *: q.y in
    let beta = q.x *: gamma in
    let alpha = small 3 *: ((q.x -: delta) *: (q.x +: delta)) in
    let x3 = (alpha *: alpha) -: (small 8 *: beta) in
    let z3 = ((q.y +: q.z) *: (q.y +: q.z)) -: gamma -: delta in
    let y3 = (alpha *: ((small 4 *: beta) -: x3)) -: (small 8 *: (gamma *: gamma)) in
    { x = x3; y = y3; z = z3 })
;;

let add q1 q2 =
  if is_infinity q1
  then q2
  else if is_infinity q2
  then q1
  else (
    let z1z1 = q1.z *: q1.z in
    let z2z2 = q2.z *: q2.z in
    let u1 = q1.x *: z2z2 in
    let u2 = q2.x *: z1z1 in
    let s1 = q1.y *: (q2.z *: z2z2) in
    let s2 = q2.y *: (q1.z *: z1z1) in
    if Z.equal u1 u2
    then if Z.equal s1 s2 then double q1 else infinity
    else (
      let h = u2 -: u1 in
      let i = small 2 *: h *: (small 2 *: h) in
      let j = h *: i in
      let r = small 2 *: (s2 -: s1) in
      let v = u1 *: i in
      let x3 = (r *: r) -: j -: (small 2 *: v) in
      let y3 = (r *: (v -: x3)) -: (small 2 *: (s1 *: j)) in
      let z3 = (((q1.z +: q2.z) *: (q1.z +: q2.z)) -: z1z1 -: z2z2) *: h in
      { x = x3; y = y3; z = z3 }))
;;

let to_affine q =
  if is_infinity q
  then None
  else (
    let zi = Z.invert q.z p in
    let zi2 = zi *: zi in
    Some (q.x *: zi2, q.y *: (zi2 *: zi)))
;;

(* [k1 * a + k2 * b] with one shared doubling chain (Shamir's trick). *)
let mul2 k1 a k2 b =
  let ab = add a b in
  let bits = Int.max (Z.numbits k1) (Z.numbits k2) in
  let acc = ref infinity in
  for i = bits - 1 downto 0 do
    acc := double !acc;
    match Z.testbit k1 i, Z.testbit k2 i with
    | false, false -> ()
    | true, false -> acc := add !acc a
    | false, true -> acc := add !acc b
    | true, true -> acc := add !acc ab
  done;
  !acc
;;

let g = of_affine (gx, gy)

type public_key = Z.t * Z.t

let compare_public_key (x1, y1) (x2, y2) =
  match Z.compare x1 x2 with
  | 0 -> Z.compare y1 y2
  | c -> c
;;

let equal_public_key a b = compare_public_key a b = 0

let to_bytes32 z =
  let h = Z.format "%064x" z in
  String.init 32 ~f:(fun i ->
    Char.of_int_exn (Int.of_string ("0x" ^ String.sub h ~pos:(2 * i) ~len:2)))
;;

let of_bytes s =
  if String.is_empty s
  then Z.zero
  else
    Z.of_string_base 16 (String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c)))
;;

let sexp_of_public_key (x, y) =
  let hex z = Z.format "%064x" z in
  [%sexp { x : string = hex x; y : string = hex y }]
;;

let on_curve (x, y) =
  Z.(geq x zero && lt x p && geq y zero && lt y p)
  && Z.equal (y *: y) ((x *: (x *: x)) -: (small 3 *: x) +: b)
;;

let coordinates (x, y) = to_bytes32 x, to_bytes32 y

let public_key_of_coordinates ~x ~y =
  if String.length x <> 32 || String.length y <> 32
  then
    Or_error.error_s
      [%message
        "P-256 coordinates must be 32 bytes each"
          ~x:(String.length x : int)
          ~y:(String.length y : int)]
  else (
    let pt = of_bytes x, of_bytes y in
    if on_curve pt then Ok pt else Or_error.error_string "P-256 point is not on the curve")
;;

let public_key_of_uncompressed s =
  if String.length s = 65 && Char.equal s.[0] '\x04'
  then
    public_key_of_coordinates
      ~x:(String.sub s ~pos:1 ~len:32)
      ~y:(String.sub s ~pos:33 ~len:32)
  else Or_error.error_string "expected a 65-byte uncompressed P-256 point"
;;

(* Strict DER: SEQUENCE [{ INTEGER, INTEGER }]. A P-256 signature is at most 72 bytes, so
   the outer length always fits the short form; integers must be positive and minimally
   encoded (a leading zero only when the next byte has its top bit set). *)
let parse_der s =
  let len = String.length s in
  let byte i = Char.to_int s.[i] in
  let read_int i =
    if i + 2 > len || byte i <> 0x02
    then None
    else (
      let l = byte (i + 1) in
      let j = i + 2 in
      if l = 0 || l >= 0x80 || j + l > len
      then None
      else if byte j >= 0x80
      then None
      else if l > 1 && byte j = 0 && byte (j + 1) < 0x80
      then None
      else Some (of_bytes (String.sub s ~pos:j ~len:l), j + l))
  in
  if len < 2 || byte 0 <> 0x30 || byte 1 >= 0x80 || byte 1 + 2 <> len
  then None
  else (
    match read_int 2 with
    | None -> None
    | Some (r, k) ->
      (match read_int k with
       | Some (s', m) when m = len -> Some (r, s')
       | _ -> None))
;;

let sha256 m = Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) m

let verify q ~message ~signature =
  match parse_der signature with
  | None -> false
  | Some (r, s) ->
    let in_range v = Z.(gt v zero && lt v n) in
    if not (in_range r && in_range s)
    then false
    else (
      let e = of_bytes (sha256 message) in
      let w = Z.invert s n in
      let u1 = Z.erem (Z.mul e w) n in
      let u2 = Z.erem (Z.mul r w) n in
      match to_affine (mul2 u1 g u2 (of_affine q)) with
      | None -> false
      | Some (x, _) -> Z.equal (Z.erem x n) r)
;;

module Testing_only = struct
  let public_key ~secret =
    let d = of_bytes secret in
    if not Z.(gt d zero && lt d n) then raise_s [%message "P-256 secret out of range"];
    Option.value_exn (to_affine (mul2 d g Z.zero g))
  ;;

  let der_int z =
    let raw = to_bytes32 z |> String.lstrip ~drop:(Char.equal '\x00') in
    let raw =
      if String.is_empty raw || Char.to_int raw.[0] >= 0x80 then "\x00" ^ raw else raw
    in
    "\x02" ^ String.of_char (Char.of_int_exn (String.length raw)) ^ raw
  ;;

  (* RFC 6979 section 3.2 with HMAC-SHA-256; for P-256 qlen = hlen = 256, so bits2int is
     the identity on 32-byte strings. *)
  let nonce ~secret ~digest =
    let hmac key data = Cryptokit.hash_string (Cryptokit.MAC.hmac_sha256 key) data in
    let x = to_bytes32 (of_bytes secret) in
    let h = to_bytes32 (Z.erem (of_bytes digest) n) in
    let v = String.make 32 '\x01' in
    let k = String.make 32 '\x00' in
    let k = hmac k (v ^ "\x00" ^ x ^ h) in
    let v = hmac k v in
    let k = hmac k (v ^ "\x01" ^ x ^ h) in
    let v = hmac k v in
    let rec loop k v =
      let v = hmac k v in
      let t = of_bytes v in
      if Z.(gt t zero && lt t n)
      then t
      else (
        let k = hmac k (v ^ "\x00") in
        loop k (hmac k v))
    in
    loop k v
  ;;

  let sign ~secret message =
    let d = of_bytes secret in
    let digest = sha256 message in
    let e = of_bytes digest in
    let k = nonce ~secret ~digest in
    let x, _ = Option.value_exn (to_affine (mul2 k g Z.zero g)) in
    let r = Z.erem x n in
    let s = Z.erem (Z.mul (Z.invert k n) (Z.add e (Z.mul r d))) n in
    let body = der_int r ^ der_int s in
    "\x30" ^ String.of_char (Char.of_int_exn (String.length body)) ^ body
  ;;
end

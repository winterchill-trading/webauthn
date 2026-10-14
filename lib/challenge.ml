open! Core

module Stable = struct
  module V1 = struct
    type t =
      { bytes : string
      ; issued_at : Time_ns.Stable.Alternate_sexp.V1.t
      ; expires_at : Time_ns.Stable.Alternate_sexp.V1.t
      }
    [@@deriving sexp, bin_io, compare, equal]
  end
end

include Stable.V1

let sexp_of_t t =
  [%sexp
    { bytes : string = Base64url.encode t.bytes
    ; issued_at : Time_ns.Alternate_sexp.t = t.issued_at
    ; expires_at : Time_ns.Alternate_sexp.t = t.expires_at
    }]
;;

let default_length = 32
let default_ttl = Time_ns.Span.of_int_sec 300
let system_random n = Cryptokit.Random.string Cryptokit.Random.secure_rng n

let create
  ?(random = system_random)
  ?(length = default_length)
  ?(ttl = default_ttl)
  ~now
  ()
  =
  if length < 16
  then raise_s [%message "Challenge.create: length below 16" (length : int)];
  let bytes = random length in
  if String.length bytes <> length
  then raise_s [%message "Challenge.create: random source returned a short string"];
  { bytes; issued_at = now; expires_at = Time_ns.add now ttl }
;;

let of_bytes ~issued_at ~expires_at bytes = { bytes; issued_at; expires_at }
let bytes t = t.bytes
let to_base64url t = Base64url.encode t.bytes
let issued_at t = t.issued_at
let expires_at t = t.expires_at

let equal_constant_time a b =
  String.length a = String.length b
  &&
  let acc = ref 0 in
  for i = 0 to String.length a - 1 do
    acc
    := !acc
       lor (Char.to_int (String.unsafe_get a i) lxor Char.to_int (String.unsafe_get b i))
  done;
  !acc = 0
;;

let check t ~now ~received =
  if not (equal_constant_time t.bytes received)
  then Error Verify_error.Challenge_mismatch
  else if Time_ns.( >= ) now t.expires_at
  then Error Verify_error.Challenge_expired
  else Ok ()
;;

open! Core

module Transport = struct
  type t =
    | Usb
    | Nfc
    | Ble
    | Smart_card
    | Hybrid
    | Internal
    | Other of string
  [@@deriving sexp, compare, equal, hash, bin_io]

  let to_string = function
    | Usb -> "usb"
    | Nfc -> "nfc"
    | Ble -> "ble"
    | Smart_card -> "smart-card"
    | Hybrid -> "hybrid"
    | Internal -> "internal"
    | Other s -> s
  ;;

  let of_string = function
    | "usb" -> Usb
    | "nfc" -> Nfc
    | "ble" -> Ble
    | "smart-card" -> Smart_card
    | "hybrid" -> Hybrid
    | "internal" -> Internal
    | s -> Other s
  ;;
end

(* A byte string whose sexp is base64url, so records print readably and stay stable. *)
module B64 = struct
  type t = string [@@deriving compare, equal, bin_io]

  let sexp_of_t s = Sexp.Atom (Base64url.encode s)

  let t_of_sexp = function
    | Sexp.Atom a as sexp ->
      (match Base64url.decode a with
       | Ok s -> s
       | Error e -> of_sexp_error (Error.to_string_hum e) sexp)
    | sexp -> of_sexp_error "expected a base64url atom" sexp
  ;;
end

module Stable = struct
  module V1 = struct
    type t =
      { id : B64.t
      ; public_key : Cose.Stable.V1.t
      ; sign_count : int
      ; user_handle : B64.t
      ; aaguid : Authenticator_data.Aaguid.Stable.V1.t
      ; transports : Transport.t list
      ; backup_eligible : bool
      ; backed_up : bool
      ; user_verified : bool
      ; attestation_format : string
      }
    [@@deriving sexp, bin_io, compare, equal]
  end
end

include Stable.V1

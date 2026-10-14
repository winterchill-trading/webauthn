(* Helpers for the vector files under [vectors/]. *)
open! Core

let of_hex h =
  String.init
    (String.length h / 2)
    ~f:(fun i ->
      Char.of_int_exn (Int.of_string ("0x" ^ String.sub h ~pos:(2 * i) ~len:2)))
;;

let to_hex s = String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c))
let json path = Yojson.Safe.from_file ("vectors/" ^ path)

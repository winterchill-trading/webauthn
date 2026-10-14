open! Core

let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

let encode s =
  let n = String.length s in
  let buf = Buffer.create (((n * 4) + 2) / 3) in
  let byte i = Char.to_int (String.unsafe_get s i) in
  let put v = Buffer.add_char buf alphabet.[v land 63] in
  let i = ref 0 in
  while !i + 2 < n do
    let v = (byte !i lsl 16) lor (byte (!i + 1) lsl 8) lor byte (!i + 2) in
    put (v lsr 18);
    put (v lsr 12);
    put (v lsr 6);
    put v;
    i := !i + 3
  done;
  (match n - !i with
   | 1 ->
     let v = byte !i lsl 16 in
     put (v lsr 18);
     put (v lsr 12)
   | 2 ->
     let v = (byte !i lsl 16) lor (byte (!i + 1) lsl 8) in
     put (v lsr 18);
     put (v lsr 12);
     put (v lsr 6)
   | _ -> ());
  Buffer.contents buf
;;

let value c =
  match c with
  | 'A' .. 'Z' -> Some (Char.to_int c - Char.to_int 'A')
  | 'a' .. 'z' -> Some (Char.to_int c - Char.to_int 'a' + 26)
  | '0' .. '9' -> Some (Char.to_int c - Char.to_int '0' + 52)
  | '-' -> Some 62
  | '_' -> Some 63
  | _ -> None
;;

let decode s =
  let s = String.rstrip s ~drop:(Char.equal '=') in
  let n = String.length s in
  match String.findi s ~f:(fun _ c -> Option.is_none (value c)) with
  | Some (position, char) ->
    Or_error.error_s
      [%message "base64url: invalid character" (char : char) (position : int)]
  | None when n % 4 = 1 ->
    Or_error.error_s [%message "base64url: impossible length" (n : int)]
  | None ->
    let buf = Buffer.create (n * 3 / 4) in
    let acc = ref 0 in
    let bits = ref 0 in
    String.iter s ~f:(fun c ->
      let v = Option.value_exn (value c) in
      acc := (!acc lsl 6) lor v land 0xFFFF;
      bits := !bits + 6;
      if !bits >= 8
      then (
        bits := !bits - 8;
        Buffer.add_char buf (Char.of_int_exn ((!acc lsr !bits) land 0xFF))));
    (* The 2 or 4 bits left over after the last full byte must be zero, otherwise two
       different strings would decode to the same bytes. *)
    if !acc land ((1 lsl !bits) - 1) <> 0
    then Or_error.error_string "base64url: non-zero trailing bits"
    else Ok (Buffer.contents buf)
;;

let decode_exn s = Or_error.ok_exn (decode s)

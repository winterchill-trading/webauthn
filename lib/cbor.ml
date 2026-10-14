open! Core

type t =
  | Int of int
  | Bytes of string
  | Text of string
  | Array of t list
  | Map of (t * t) list
  | Tag of int * t
  | Bool of bool
  | Null
  | Undefined
  | Simple of int
  | Float of float
[@@deriving sexp, compare, equal]

let max_depth = 32

let kind = function
  | Int _ -> "int"
  | Bytes _ -> "bytes"
  | Text _ -> "text"
  | Array _ -> "array"
  | Map _ -> "map"
  | Tag _ -> "tag"
  | Bool _ -> "bool"
  | Null -> "null"
  | Undefined -> "undefined"
  | Simple _ -> "simple"
  | Float _ -> "float"
;;

(* Half-precision floats (IEEE 754 binary16), RFC 8949 appendix D. *)
let float_of_half h =
  let exp = (h lsr 10) land 0x1f in
  let mant = h land 0x3ff in
  let v =
    if exp = 0
    then Float.ldexp (Float.of_int mant) (-24)
    else if exp <> 31
    then Float.ldexp (Float.of_int (mant + 1024)) (exp - 25)
    else if mant = 0
    then Float.infinity
    else Float.nan
  in
  if h land 0x8000 <> 0 then Float.neg v else v
;;

exception Decode_error of Sexp.t

let fail msg = raise (Decode_error msg)

let decode_prefix_exn s ~pos =
  let len = String.length s in
  let pos = ref pos in
  let need n =
    if n < 0 || n > len - !pos
    then
      fail
        [%message
          "CBOR: truncated input"
            ~at:(!pos : int)
            ~needed:(n : int)
            ~available:(len - !pos : int)]
  in
  let byte () =
    need 1;
    let b = Char.to_int s.[!pos] in
    incr pos;
    b
  in
  let uint n =
    need n;
    let v = ref 0 in
    for i = 0 to n - 1 do
      let b = Char.to_int s.[!pos + i] in
      (* An 8-byte argument can exceed OCaml's 63-bit int; refuse rather than wrap. *)
      if !v lsr 55 <> 0 then fail [%message "CBOR: integer out of range" ~at:(!pos : int)];
      v := (!v lsl 8) lor b
    done;
    if !v < 0 then fail [%message "CBOR: integer out of range" ~at:(!pos : int)];
    pos := !pos + n;
    !v
  in
  (* Returns [None] for an indefinite length (additional information 31). *)
  let argument ai =
    if ai < 24
    then Some ai
    else (
      match ai with
      | 24 -> Some (uint 1)
      | 25 -> Some (uint 2)
      | 26 -> Some (uint 4)
      | 27 -> Some (uint 8)
      | 31 -> None
      | _ ->
        fail
          [%message
            "CBOR: reserved additional information" (ai : int) ~at:(!pos - 1 : int)])
  in
  let take n =
    need n;
    let v = String.sub s ~pos:!pos ~len:n in
    pos := !pos + n;
    v
  in
  let is_break () = !pos < len && Char.equal s.[!pos] '\xff' in
  let text_of start v =
    if Stdlib.String.is_valid_utf_8 v
    then v
    else fail [%message "CBOR: text string is not valid UTF-8" ~at:(start : int)]
  in
  (* Reads [n] items in input order. [List.init] is not used because Core's calls its
     function from the last index down. *)
  let read_n n f =
    let rec loop i acc = if i = n then List.rev acc else loop (i + 1) (f () :: acc) in
    loop 0 []
  in
  let rec item ~depth =
    if depth > max_depth then fail [%message "CBOR: nesting too deep" ~at:(!pos : int)];
    let start = !pos in
    let ib = byte () in
    let major = ib lsr 5 in
    let ai = ib land 31 in
    let definite what =
      match argument ai with
      | Some n -> n
      | None ->
        fail [%message "CBOR: indefinite length not allowed" what ~at:(start : int)]
    in
    match major with
    | 0 -> Int (definite "for an integer")
    | 1 -> Int (-1 - definite "for an integer")
    | 2 | 3 ->
      let raw =
        match argument ai with
        | Some n -> take n
        | None ->
          let buf = Buffer.create 64 in
          while not (is_break ()) do
            let chunk_start = !pos in
            let cb = byte () in
            if cb lsr 5 <> major || cb land 31 = 31
            then
              fail
                [%message
                  "CBOR: indefinite string chunk of another type" ~at:(chunk_start : int)];
            match argument (cb land 31) with
            | Some n ->
              let chunk = take n in
              if major = 3 then ignore (text_of chunk_start chunk : string);
              Buffer.add_string buf chunk
            | None -> assert false
          done;
          pos := !pos + 1;
          Buffer.contents buf
      in
      if major = 2 then Bytes raw else Text (text_of start raw)
    | 4 ->
      (match argument ai with
       | Some n ->
         (* Every item takes at least one byte; checking up front keeps a hostile length
            from driving a long loop. *)
         need n;
         Array (read_n n (fun () -> item ~depth:(depth + 1)))
       | None ->
         let rec loop acc =
           if is_break ()
           then (
             pos := !pos + 1;
             List.rev acc)
           else loop (item ~depth:(depth + 1) :: acc)
         in
         Array (loop []))
    | 5 ->
      let seen = Hash_set.Poly.create () in
      let entry () =
        let key_at = !pos in
        let k = item ~depth:(depth + 1) in
        let v = item ~depth:(depth + 1) in
        if Hash_set.mem seen k
        then fail [%message "CBOR: duplicate map key" ~at:(key_at : int)];
        Hash_set.add seen k;
        k, v
      in
      (match argument ai with
       | Some n ->
         need (2 * n);
         Map (read_n n entry)
       | None ->
         let rec loop acc =
           if is_break ()
           then (
             pos := !pos + 1;
             List.rev acc)
           else loop (entry () :: acc)
         in
         Map (loop []))
    | 6 ->
      let tag = definite "for a tag" in
      Tag (tag, item ~depth:(depth + 1))
    | _ ->
      (match ai with
       | 20 -> Bool false
       | 21 -> Bool true
       | 22 -> Null
       | 23 -> Undefined
       | n when n < 20 -> Simple n
       | 24 ->
         let n = uint 1 in
         if n < 32
         then
           fail
             [%message "CBOR: two-byte simple value below 32" (n : int) ~at:(start : int)];
         Simple n
       | 25 -> Float (float_of_half (uint 2))
       | 26 -> Float (Int32.float_of_bits (Int32.of_int_trunc (uint 4)))
       | 27 ->
         need 8;
         let v = ref 0L in
         for i = 0 to 7 do
           let b = Int64.of_int (Char.to_int s.[!pos + i]) in
           v := Int64.(bit_or (shift_left !v 8) b)
         done;
         pos := !pos + 8;
         Float (Int64.float_of_bits !v)
       | 31 -> fail [%message "CBOR: unexpected break" ~at:(start : int)]
       | _ ->
         fail
           [%message "CBOR: reserved additional information" (ai : int) ~at:(start : int)])
  in
  let v = item ~depth:0 in
  v, !pos
;;

let decode_prefix s ~pos =
  if pos < 0 || pos > String.length s
  then Or_error.error_s [%message "CBOR: position out of bounds" (pos : int)]
  else (
    match decode_prefix_exn s ~pos with
    | r -> Ok r
    | exception Decode_error e -> Error (Error.create_s e))
;;

let decode s =
  let%bind.Or_error v, stop = decode_prefix s ~pos:0 in
  if stop = String.length s
  then Ok v
  else
    Or_error.error_s
      [%message "CBOR: trailing bytes" ~at:(stop : int) ~total:(String.length s : int)]
;;

(* Encoding *)

let head buf major n =
  let m = major lsl 5 in
  let add_be bytes =
    for i = bytes - 1 downto 0 do
      Buffer.add_char buf (Char.of_int_exn ((n lsr (8 * i)) land 0xff))
    done
  in
  if n < 24
  then Buffer.add_char buf (Char.of_int_exn (m lor n))
  else if n < 0x100
  then (
    Buffer.add_char buf (Char.of_int_exn (m lor 24));
    add_be 1)
  else if n < 0x10000
  then (
    Buffer.add_char buf (Char.of_int_exn (m lor 25));
    add_be 2)
  else if n < 0x1_0000_0000
  then (
    Buffer.add_char buf (Char.of_int_exn (m lor 26));
    add_be 4)
  else (
    Buffer.add_char buf (Char.of_int_exn (m lor 27));
    add_be 8)
;;

(* The binary16 pattern for [f] when it holds [f] exactly. *)
let half_of_float f =
  if Float.is_nan f
  then Some 0x7e00
  else (
    let b = Int32.to_int_trunc (Int32.bits_of_float f) land 0xffff_ffff in
    let sign = (b lsr 16) land 0x8000 in
    let exp = (b lsr 23) land 0xff in
    let mant = b land 0x7f_ffff in
    let candidate =
      if exp = 0xff
      then Some (sign lor 0x7c00)
      else if exp = 0 && mant = 0
      then Some sign
      else (
        let e = exp - 127 + 15 in
        if e >= 31
        then None
        else if e <= 0
        then if e < -10 then None else Some (sign lor ((mant lor 0x80_0000) lsr (14 - e)))
        else Some (sign lor (e lsl 10) lor (mant lsr 13)))
    in
    Option.filter candidate ~f:(fun h -> Float.equal (float_of_half h) f))
;;

let rec encode_into buf = function
  | Int n -> if n >= 0 then head buf 0 n else head buf 1 (-1 - n)
  | Bytes b ->
    head buf 2 (String.length b);
    Buffer.add_string buf b
  | Text s ->
    head buf 3 (String.length s);
    Buffer.add_string buf s
  | Array items ->
    head buf 4 (List.length items);
    List.iter items ~f:(encode_into buf)
  | Map entries ->
    head buf 5 (List.length entries);
    List.map entries ~f:(fun (k, v) -> encode k, v)
    |> List.sort ~compare:(fun (a, _) (b, _) -> String.compare a b)
    |> List.iter ~f:(fun (k, v) ->
      Buffer.add_string buf k;
      encode_into buf v)
  | Tag (tag, v) ->
    head buf 6 tag;
    encode_into buf v
  | Bool false -> Buffer.add_char buf '\xf4'
  | Bool true -> Buffer.add_char buf '\xf5'
  | Null -> Buffer.add_char buf '\xf6'
  | Undefined -> Buffer.add_char buf '\xf7'
  | Simple n -> head buf 7 n
  | Float f ->
    (match half_of_float f with
     | Some h ->
       Buffer.add_char buf '\xf9';
       Buffer.add_char buf (Char.of_int_exn (h lsr 8));
       Buffer.add_char buf (Char.of_int_exn (h land 0xff))
     | None ->
       let single = Int32.bits_of_float f in
       let add_bits bits n =
         for i = n - 1 downto 0 do
           Buffer.add_char
             buf
             (Char.of_int_exn
                (Int64.to_int_trunc
                   (Int64.bit_and (Int64.shift_right_logical bits (8 * i)) 0xffL)))
         done
       in
       if Float.equal (Int32.float_of_bits single) f
       then (
         Buffer.add_char buf '\xfa';
         add_bits (Int64.of_int32 single) 4)
       else (
         Buffer.add_char buf '\xfb';
         add_bits (Int64.bits_of_float f) 8))

and encode t =
  let buf = Buffer.create 64 in
  encode_into buf t;
  Buffer.contents buf
;;

let rec diagnostic = function
  | Int n -> Int.to_string n
  | Bytes b ->
    "h'" ^ String.concat_map b ~f:(fun c -> sprintf "%02x" (Char.to_int c)) ^ "'"
  | Text s -> sprintf "%S" s
  | Array items -> "[" ^ String.concat ~sep:", " (List.map items ~f:diagnostic) ^ "]"
  | Map entries ->
    "{"
    ^ String.concat
        ~sep:", "
        (List.map entries ~f:(fun (k, v) -> diagnostic k ^ ": " ^ diagnostic v))
    ^ "}"
  | Tag (tag, v) -> sprintf "%d(%s)" tag (diagnostic v)
  | Bool b -> Bool.to_string b
  | Null -> "null"
  | Undefined -> "undefined"
  | Simple n -> sprintf "simple(%d)" n
  | Float f ->
    if Float.is_nan f
    then "NaN"
    else if Float.is_inf f
    then if Float.( > ) f 0. then "Infinity" else "-Infinity"
    else if Float.is_integer f && Float.( < ) (Float.abs f) 1e16
    then sprintf "%.0f.0" f
    else (
      let s = sprintf "%.17g" f in
      let s =
        (* Prefer the shortest digits that read back to the same value. *)
        List.find_map
          [ 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16 ]
          ~f:(fun d ->
            let c = sprintf "%.*g" d f in
            if Float.equal (Float.of_string c) f then Some c else None)
        |> Option.value ~default:s
      in
      if String.exists s ~f:(fun c -> Char.equal c '.' || Char.equal c 'e')
      then s
      else s ^ ".0")
;;

let find entries key =
  List.find_map entries ~f:(fun (k, v) -> if equal k key then Some v else None)
;;

let expected what t =
  Or_error.error_s
    [%message "CBOR: unexpected item" ~expected:(what : string) ~got:(kind t)]
;;

let to_int = function
  | Int n -> Ok n
  | t -> expected "int" t
;;

let to_bytes = function
  | Bytes b -> Ok b
  | t -> expected "bytes" t
;;

let to_text = function
  | Text s -> Ok s
  | t -> expected "text" t
;;

let to_map = function
  | Map m -> Ok m
  | t -> expected "map" t
;;

let to_array = function
  | Array a -> Ok a
  | t -> expected "array" t
;;

let quickcheck_generator =
  let open Quickcheck.Generator.Let_syntax in
  let utf8 =
    let%map chars =
      List.gen_with_length
        3
        (Quickcheck.Generator.of_list
           [ "a"; "Z"; "0"; " "; "\xc3\xa9"; "\xe2\x82\xac"; "\xf0\x9f\x94\x91" ])
    in
    String.concat chars
  in
  let leaf =
    Quickcheck.Generator.union
      [ (let%map n = Int.quickcheck_generator in
         Int n)
      ; (let%map b = String.quickcheck_generator in
         Bytes b)
      ; (let%map s = utf8 in
         Text s)
      ; (let%map b = Bool.quickcheck_generator in
         Bool b)
      ; return Null
      ; return Undefined
      ; (let%map n =
           Quickcheck.Generator.union [ Int.gen_incl 0 19; Int.gen_incl 32 255 ]
         in
         Simple n)
      ; (let%map f = Float.gen_finite in
         Float f)
      ]
  in
  Quickcheck.Generator.recursive_union [ leaf ] ~f:(fun self ->
    let small = self in
    [ (let%map items = List.quickcheck_generator small in
       Array items)
    ; (let%map entries =
         List.quickcheck_generator (Quickcheck.Generator.both small small)
       in
       Map (List.dedup_and_sort entries ~compare:(fun (a, _) (b, _) -> compare a b)))
    ; (let%map tag = Int.gen_incl 0 100_000
       and v = small in
       Tag (tag, v))
    ])
;;

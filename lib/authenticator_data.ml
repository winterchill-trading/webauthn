open! Core

module Flags = struct
  type t =
    { user_present : bool
    ; user_verified : bool
    ; backup_eligible : bool
    ; backed_up : bool
    ; attested_credential_data : bool
    ; extension_data : bool
    }
  [@@deriving sexp, compare, equal]

  let of_byte b =
    let bit i = b land (1 lsl i) <> 0 in
    { user_present = bit 0
    ; user_verified = bit 2
    ; backup_eligible = bit 3
    ; backed_up = bit 4
    ; attested_credential_data = bit 6
    ; extension_data = bit 7
    }
  ;;

  let to_byte t =
    let bit i v = if v then 1 lsl i else 0 in
    bit 0 t.user_present
    lor bit 2 t.user_verified
    lor bit 3 t.backup_eligible
    lor bit 4 t.backed_up
    lor bit 6 t.attested_credential_data
    lor bit 7 t.extension_data
  ;;
end

let to_hex s = String.concat_map s ~f:(fun c -> sprintf "%02x" (Char.to_int c))

module Aaguid = struct
  module T = struct
    type t = string [@@deriving compare, equal, hash, bin_io]

    let to_string t =
      let h = to_hex t in
      String.concat
        ~sep:"-"
        [ String.sub h ~pos:0 ~len:8
        ; String.sub h ~pos:8 ~len:4
        ; String.sub h ~pos:12 ~len:4
        ; String.sub h ~pos:16 ~len:4
        ; String.sub h ~pos:20 ~len:12
        ]
    ;;

    let of_bytes s =
      if String.length s = 16
      then Ok s
      else
        Or_error.error_s [%message "AAGUID must be 16 bytes" ~got:(String.length s : int)]
    ;;

    let of_string s =
      let hex = String.filter s ~f:(fun c -> not (Char.equal c '-')) in
      if String.length s <> 36
         || String.length hex <> 32
         || not (String.for_all hex ~f:Char.is_hex_digit)
      then Or_error.error_s [%message "AAGUID: expected UUID text" s]
      else
        Ok
          (String.init 16 ~f:(fun i ->
             Char.of_int_exn (Int.of_string ("0x" ^ String.sub hex ~pos:(2 * i) ~len:2))))
    ;;

    let sexp_of_t t = Sexp.Atom (to_string t)

    let t_of_sexp = function
      | Sexp.Atom s as sexp ->
        (match of_string s with
         | Ok t -> t
         | Error e -> of_sexp_error (Error.to_string_hum e) sexp)
      | sexp -> of_sexp_error "AAGUID: expected an atom" sexp
    ;;
  end

  include T

  let to_bytes t = t
  let zero = String.make 16 '\x00'

  module Stable = struct
    module V1 = T
  end
end

type attested_credential =
  { aaguid : Aaguid.t
  ; credential_id : string
  ; public_key : Cose.t
  }

let sexp_of_attested_credential { aaguid; credential_id; public_key } =
  [%sexp
    { aaguid : Aaguid.t
    ; credential_id : string = Base64url.encode credential_id
    ; public_key : Cose.t
    }]
;;

type t =
  { rp_id_hash : string
  ; flags : Flags.t
  ; sign_count : int
  ; attested_credential : attested_credential option
  ; extensions : Cbor.t option
  }

let sexp_of_t { rp_id_hash; flags; sign_count; attested_credential; extensions } =
  [%sexp
    { rp_id_hash : string = to_hex rp_id_hash
    ; flags : Flags.t
    ; sign_count : int
    ; attested_credential : attested_credential option
    ; extensions : Cbor.t option
    }]
;;

let max_credential_id_length = 1023
let header_length = 37

let parse s =
  let open Or_error.Let_syntax in
  let len = String.length s in
  if len < header_length
  then
    Or_error.error_s
      [%message "authenticator data shorter than 37 bytes" ~length:(len : int)]
  else (
    let byte i = Char.to_int s.[i] in
    let flags = Flags.of_byte (byte 32) in
    let sign_count =
      (byte 33 lsl 24) lor (byte 34 lsl 16) lor (byte 35 lsl 8) lor byte 36
    in
    let%bind attested_credential, pos =
      if not flags.attested_credential_data
      then Ok (None, header_length)
      else if len < header_length + 18
      then Or_error.error_string "authenticator data: attested credential data truncated"
      else (
        let aaguid = String.sub s ~pos:header_length ~len:16 in
        let id_len = (byte 53 lsl 8) lor byte 54 in
        if id_len = 0 || id_len > max_credential_id_length
        then
          Or_error.error_s
            [%message "authenticator data: bad credential ID length" (id_len : int)]
        else if 55 + id_len > len
        then Or_error.error_string "authenticator data: credential ID truncated"
        else (
          let credential_id = String.sub s ~pos:55 ~len:id_len in
          let%bind key_item, after_key =
            Cbor.decode_prefix s ~pos:(55 + id_len)
            |> Or_error.tag ~tag:"authenticator data: credential public key"
          in
          let%map public_key = Cose.of_cbor key_item in
          Some { aaguid; credential_id; public_key }, after_key))
    in
    let%bind extensions, pos =
      if not flags.extension_data
      then Ok (None, pos)
      else (
        let%bind item, after =
          Cbor.decode_prefix s ~pos |> Or_error.tag ~tag:"authenticator data: extensions"
        in
        match item with
        | Map _ -> Ok (Some item, after)
        | other ->
          Or_error.error_s
            [%message
              "authenticator data: extensions must be a map" ~got:(Cbor.kind other)])
    in
    if pos <> len
    then
      Or_error.error_s
        [%message
          "authenticator data: trailing bytes" ~at:(pos : int) ~length:(len : int)]
    else
      Ok
        { rp_id_hash = String.sub s ~pos:0 ~len:32
        ; flags
        ; sign_count
        ; attested_credential
        ; extensions
        })
;;

let encode t =
  let buf = Buffer.create 256 in
  Buffer.add_string buf t.rp_id_hash;
  let flags =
    { t.flags with
      attested_credential_data = Option.is_some t.attested_credential
    ; extension_data = Option.is_some t.extensions
    }
  in
  Buffer.add_char buf (Char.of_int_exn (Flags.to_byte flags));
  for i = 3 downto 0 do
    Buffer.add_char buf (Char.of_int_exn ((t.sign_count lsr (8 * i)) land 0xff))
  done;
  Option.iter t.attested_credential ~f:(fun a ->
    Buffer.add_string buf a.aaguid;
    let l = String.length a.credential_id in
    Buffer.add_char buf (Char.of_int_exn ((l lsr 8) land 0xff));
    Buffer.add_char buf (Char.of_int_exn (l land 0xff));
    Buffer.add_string buf a.credential_id;
    Buffer.add_string buf (Cose.encode a.public_key));
  Option.iter t.extensions ~f:(fun e -> Buffer.add_string buf (Cbor.encode e));
  Buffer.contents buf
;;

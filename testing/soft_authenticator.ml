open! Core
open Webauthn

type signer =
  | Ec of string (* 32-byte secret *)
  | Rsa of Cryptokit.RSA.key

type t =
  { signer : signer
  ; public_key : Cose.t
  ; credential_id : string
  ; aaguid : Authenticator_data.Aaguid.t
  ; backup_eligible : bool
  ; counting : bool
  ; mutable counter : int
  }

let sha256 s = Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) s

let create
  ?(algorithm = Cose.Algorithm.Es256)
  ?(aaguid = Authenticator_data.Aaguid.zero)
  ?(backup_eligible = true)
  ?(counting = true)
  ?credential_id
  ~seed
  ()
  =
  let signer, public_key =
    match algorithm with
    | Es256 ->
      (* SHA-256 of the seed is below the group order with overwhelming probability; a
         seed for which it is not would raise in [public_key]. *)
      let secret = sha256 ("es256 key " ^ seed) in
      Ec secret, Cose.Es256 (P256.Testing_only.public_key ~secret)
    | Rs256 ->
      let rng = Cryptokit.Random.pseudo_rng (sha256 ("rs256 key " ^ seed)) in
      (* Cryptokit's [new_key 2048] multiplies two 1024-bit primes, which can give a
         2047-bit modulus; draw again until the modulus has the full size. *)
      let rec draw () =
        let key = Cryptokit.RSA.new_key ~rng ~e:65537 2048 in
        let top = Char.to_int (String.lstrip key.n ~drop:(Char.equal '\x00')).[0] in
        if String.length (String.lstrip key.n ~drop:(Char.equal '\x00')) = 256
           && top >= 0x80
        then key
        else draw ()
      in
      let key = draw () in
      let public_key =
        Rsa.public_key ~n:key.n ~e:key.e |> Or_error.ok_exn |> fun k -> Cose.Rs256 k
      in
      Rsa key, public_key
  in
  { signer
  ; public_key
  ; credential_id =
      Option.value
        credential_id
        ~default:(String.prefix (sha256 ("credential id " ^ seed)) 16)
  ; aaguid
  ; backup_eligible
  ; counting
  ; counter = 0
  }
;;

let credential_id t = t.credential_id
let public_key t = t.public_key
let sign_count t = t.counter

(* DigestInfo prefix for SHA-256, RFC 8017 section 9.2 note 1. *)
let digest_info =
  "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
;;

let sign t message =
  match t.signer with
  | Ec secret -> P256.Testing_only.sign ~secret message
  | Rsa key ->
    let k = key.size / 8 in
    let tt = digest_info ^ sha256 message in
    let em = "\x00\x01" ^ String.make (k - String.length tt - 3) '\xff' ^ "\x00" ^ tt in
    Cryptokit.RSA.sign key em
;;

let client_data ~type_ ~challenge ~origin ~cross_origin ~top_origin =
  Client_data.to_json { type_; challenge; origin; cross_origin; top_origin }
;;

let flags ~user_present ~user_verified ~backup_eligible ~backed_up
  : Authenticator_data.Flags.t
  =
  { user_present
  ; user_verified
  ; backup_eligible
  ; backed_up
  ; attested_credential_data = false
  ; extension_data = false
  }
;;

let register
  ?(type_ = "webauthn.create")
  ?(cross_origin = false)
  ?top_origin
  ?rp_id_hash_of
  ?(user_present = true)
  ?(user_verified = true)
  ?backed_up
  ?(attestation = `None)
  ?(transports = [ Credential.Transport.Internal ])
  ?raw_id
  t
  ~rp_id
  ~origin
  ~challenge
  ()
  : Response.Registration.t
  =
  let client_data_json =
    client_data ~type_ ~challenge ~origin ~cross_origin ~top_origin
  in
  let auth_data =
    Authenticator_data.encode
      { rp_id_hash = sha256 (Option.value rp_id_hash_of ~default:rp_id)
      ; flags =
          flags
            ~user_present
            ~user_verified
            ~backup_eligible:t.backup_eligible
            ~backed_up:(Option.value backed_up ~default:t.backup_eligible)
      ; sign_count = t.counter
      ; attested_credential =
          Some
            { aaguid = t.aaguid
            ; credential_id = t.credential_id
            ; public_key = t.public_key
            }
      ; extensions = None
      }
  in
  let signed = auth_data ^ sha256 client_data_json in
  let alg = Cbor.Int (Cose.Algorithm.to_int (Cose.algorithm t.public_key)) in
  let fmt, statement =
    match attestation with
    | `None -> "none", []
    | `Packed_self ->
      "packed", [ Cbor.Text "alg", alg; Text "sig", Bytes (sign t signed) ]
    | `Packed_self_bad_signature ->
      "packed", [ Cbor.Text "alg", alg; Text "sig", Bytes (sign t (signed ^ "x")) ]
    | `Format name -> name, []
  in
  let raw_id = Option.value raw_id ~default:t.credential_id in
  { id = Base64url.encode raw_id
  ; raw_id
  ; client_data_json
  ; attestation_object = Attestation.encode { fmt; auth_data; statement }
  ; transports
  ; authenticator_attachment = Some "platform"
  ; client_extension_results = `Assoc [ "credProps", `Assoc [ "rk", `Bool true ] ]
  }
;;

let authenticate
  ?(type_ = "webauthn.get")
  ?(cross_origin = false)
  ?top_origin
  ?rp_id_hash_of
  ?(user_present = true)
  ?(user_verified = true)
  ?backup_eligible
  ?backed_up
  ?sign_count
  ?user_handle
  ?raw_id
  ?(tamper_signature = false)
  t
  ~rp_id
  ~origin
  ~challenge
  ()
  : Response.Authentication.t
  =
  if t.counting then t.counter <- t.counter + 1;
  let backup_eligible = Option.value backup_eligible ~default:t.backup_eligible in
  let client_data_json =
    client_data ~type_ ~challenge ~origin ~cross_origin ~top_origin
  in
  let authenticator_data =
    Authenticator_data.encode
      { rp_id_hash = sha256 (Option.value rp_id_hash_of ~default:rp_id)
      ; flags =
          flags
            ~user_present
            ~user_verified
            ~backup_eligible
            ~backed_up:(Option.value backed_up ~default:backup_eligible)
      ; sign_count = Option.value sign_count ~default:t.counter
      ; attested_credential = None
      ; extensions = None
      }
  in
  let signature = sign t (authenticator_data ^ sha256 client_data_json) in
  let signature =
    if tamper_signature
    then (
      let b = Bytes.of_string signature in
      let i = Bytes.length b - 1 in
      Bytes.set b i (Char.of_int_exn (Char.to_int (Bytes.get b i) lxor 1));
      Bytes.to_string b)
    else signature
  in
  let raw_id = Option.value raw_id ~default:t.credential_id in
  { id = Base64url.encode raw_id
  ; raw_id
  ; client_data_json
  ; authenticator_data
  ; signature
  ; user_handle
  ; authenticator_attachment = Some "platform"
  ; client_extension_results = `Assoc []
  }
;;

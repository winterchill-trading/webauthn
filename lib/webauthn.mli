(** WebAuthn and passkey relying-party verification.

    A relying party (the web service) uses this library in two ceremonies:

    - {b registration}: issue a {!Challenge}, send {!Options.Creation} JSON, receive a
      {!Response.Registration}, check it with {!Registration.verify} and keep the
      resulting {!Credential} in a {!Store};
    - {b authentication}: issue a challenge, send {!Options.Request} JSON, receive a
      {!Response.Authentication}, look the credential up by its ID, check the assertion
      with {!Authentication.verify} and write the updated record back.

    The lower layers are usable on their own: {!Base64url}, {!Cbor}, {!Cose}, {!P256},
    {!Rsa}, {!Authenticator_data}, {!Client_data}, {!Attestation}. *)

(** Unpadded base64url, strict decoding. *)
module Base64url = Base64url

(** RFC 8949 CBOR decoder and deterministic encoder. *)
module Cbor = Cbor

(** ECDSA P-256 / SHA-256 verification (ES256). *)
module P256 = P256

(** RSASSA-PKCS1-v1_5 / SHA-256 verification (RS256). *)
module Rsa = Rsa

(** COSE public keys and algorithm identifiers. *)
module Cose = Cose

(** Authenticator data: RP ID hash, flags, counter, attested credential. *)
module Authenticator_data = Authenticator_data

(** clientDataJSON. *)
module Client_data = Client_data

(** Why a response was refused, with stable codes. *)
module Verify_error = Verify_error

(** Challenges: CSPRNG bytes with an expiry. *)
module Challenge = Challenge

(** The stored credential record. *)
module Credential = Credential

(** Browser responses ([PublicKeyCredential.toJSON()]). *)
module Response = Response

(** JSON options for [navigator.credentials.create] and [get]. *)
module Options = Options

(** RP ID and allowed origins. *)
module Relying_party = Relying_party

(** Attestation objects and statement verification. *)
module Attestation = Attestation

(** Registration ceremony verification. *)
module Registration = Registration

(** Authentication (assertion) verification. *)
module Authentication = Authentication

(** Credential store interface. *)
module Store = Store

(** In-memory credential store. *)
module Store_memory = Store_memory

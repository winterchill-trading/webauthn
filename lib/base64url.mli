(** Unpadded base64url (RFC 4648 section 5), the encoding WebAuthn uses for every byte
    string that crosses JSON: challenges, credential ids, user handles and the [response]
    fields of a [PublicKeyCredential]. *)

open! Core

(** [encode s] is [s] in the URL-safe alphabet without [=] padding. *)
val encode : string -> string

(** [decode s] accepts the URL-safe alphabet with or without trailing [=] padding.

    It rejects the standard alphabet ([+] and [/]), whitespace, and inputs whose last
    character carries non-zero unused bits, so every byte string has exactly one accepted
    encoding apart from optional padding. *)
val decode : string -> string Or_error.t

(** [decode_exn s] is [decode s] raising on error, for literals in tests. *)
val decode_exn : string -> string

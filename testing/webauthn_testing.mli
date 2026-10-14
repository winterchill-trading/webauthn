(** Test helpers for relying parties built on [webauthn]: a software authenticator and a
    conformance suite for {!Webauthn.Store.S} implementations. Not for production use. *)

(** Produces registration and authentication responses, valid or deliberately broken. *)
module Soft_authenticator = Soft_authenticator

(** Scenarios every credential store must pass. *)
module Store_conformance = Store_conformance
